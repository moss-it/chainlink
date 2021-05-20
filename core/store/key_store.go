package store

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.uber.org/multierr"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/postgres"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/utils"
)

// EthereumMessageHashPrefix is a Geth-originating message prefix that seeks to
// prevent arbitrary message data to be representable as a valid Ethereum transaction
// For more information, see: https://github.com/ethereum/go-ethereum/issues/3731
const EthereumMessageHashPrefix = "\x19Ethereum Signed Message:\n32"

// ErrKeyStoreLocked is returned if you call a method that requires unlocked keys before you unlocked the keystore
var ErrKeyStoreLocked = errors.New("keystore is locked (HINT: did you forget to call keystore.Unlock?)")

//go:generate mockery --name KeyStoreInterface --output ../internal/mocks/ --case=underscore
// KeyStoreInterface is the external interface for KeyStore
type KeyStoreInterface interface {
	Unlock(password string) error
	HasAccounts() bool
	HasAccountWithAddress(common.Address) bool
	CreateNewAccount() (accounts.Account, error)
	ImportKey(keyJSON []byte, oldPassword string) (accounts.Account, error)
	Export(address common.Address, newPassword string) ([]byte, error)
	DeleteKey(address common.Address) error
	ArchiveKey(address common.Address) error
	GetAccounts() []accounts.Account
	GetAccountByAddress(common.Address) (accounts.Account, error)
	EnsureFundingAccount() (acct accounts.Account, didExist bool, err error)

	SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	UnlockedKeys() (keys []models.Key, err error)
	SendKeys() (keys []models.Key, err error)
	FundingKeys() (keys []models.Key, err error)
	KeyByAddress(address common.Address) (models.Key, error)
	GetRoundRobinAddress(db *gorm.DB, addresses ...common.Address) (address common.Address, err error)

	SyncDiskKeyStoreToDB() error
}

// KeyStore manages a key storage directory on disk.
type KeyStore struct {
	gethKeyStore *keystore.KeyStore
	db           *gorm.DB
	password     string
	scryptParams utils.ScryptParams
	keyDir       string
	keys         []models.Key
}

// NewKeyStore creates a keystore for the given directory.
func NewKeyStore(db *gorm.DB, keyDir string, scryptParams utils.ScryptParams) *KeyStore {
	ks := keystore.NewKeyStore(keyDir, scryptParams.N, scryptParams.P)
	return &KeyStore{ks, db, "", scryptParams, keyDir, make([]models.Key, 0)}
}

// NewInsecureKeyStore creates an *INSECURE* keystore for the given directory.
// NOTE: Should only be used for testing!
func NewInsecureKeyStore(db *gorm.DB, keyDir string) *KeyStore {
	return NewKeyStore(db, keyDir, utils.FastScryptParams)
}

// HasAccounts returns true if there are accounts located at the keystore
// directory.
func (ks *KeyStore) HasAccounts() bool {
	return len(ks.gethKeyStore.Accounts()) > 0
}

// Unlock loads keys from the database, and uses the given password to try to
// unlock accounts located in the keystore directory.
func (ks *KeyStore) Unlock(password string) (merr error) {
	var keyMap map[common.Address]models.Key
	keyMap, merr = ks.loadDBKeys()
	if merr != nil {
		return errors.Wrap(merr, "KeyStore failed to load keys from database")
	}
	for _, account := range ks.gethKeyStore.Accounts() {
		if k, exists := keyMap[account.Address]; exists {
			ks.keys = append(ks.keys, k)
		} else {
			merr = multierr.Combine(merr, errors.Errorf("could not load key from database", account.Address.Hex()))
			continue
		}
		err := ks.gethKeyStore.Unlock(account, password)
		if err != nil {
			merr = multierr.Combine(merr, errors.Errorf("invalid password for account %s", account.Address.Hex()), err)
		} else {
			logger.Infow(fmt.Sprint("Unlocked account ", account.Address.Hex()), "address", account.Address.Hex())
		}
	}
	sort.Slice(ks.keys, func(i, j int) bool {
		if ks.keys[i].CreatedAt == ks.keys[j].CreatedAt {
			return bytes.Compare(ks.keys[i].Address.Bytes(), ks.keys[j].Address.Bytes()) < 0
		}
		return ks.keys[i].CreatedAt.Before(ks.keys[j].CreatedAt)
	})
	ks.password = password
	return merr
}

// CreateNewAccount adds an account to the underlying geth keystore (which
// writes the file to disk) and inserts the new key to the database
func (ks *KeyStore) CreateNewAccount() (acct accounts.Account, err error) {
	if ks.password == "" {
		return acct, ErrKeyStoreLocked
	}
	return ks.createNewAccount(false)
}

// EnsureFundingAccount ensures that a funding account exists, and returns it
func (ks *KeyStore) EnsureFundingAccount() (acct accounts.Account, didExist bool, err error) {
	if ks.password == "" {
		return acct, false, ErrKeyStoreLocked
	}
	found, err := ks.getFundingAccount()
	if err != nil {
		return acct, false, err
	} else if found != nil {
		return *found, true, nil
	}
	acct, err = ks.createNewAccount(true)
	return acct, false, nil
}

func (ks *KeyStore) getFundingAccount() (*accounts.Account, error) {
	fundingKeys, err := ks.FundingKeys()
	if err != nil {
		return nil, err
	}
	if len(fundingKeys) > 0 {
		a, err := ks.GetAccountByAddress(fundingKeys[0].Address.Address())
		return &a, err
	}
	return nil, nil
}

func (ks *KeyStore) createNewAccount(isFunding bool) (acct accounts.Account, err error) {
	acct, err = ks.gethKeyStore.NewAccount(ks.password)
	if err != nil {
		return acct, err
	}
	if err = ks.gethKeyStore.Unlock(acct, ks.password); err != nil {
		return acct, err
	}
	exportedJSON, err := ks.Export(acct.Address, ks.password)
	if err != nil {
		return acct, err
	}
	// HACK: One bug in this approach is that for funding accounts, if we
	// crash between NewAccount above and this line below, on reboot the
	// chainlink node will load the key from disk and insert it as a regular
	// (not funding) key
	// See: https://app.clubhouse.io/chainlinklabs/story/9963/keystore-bptxm-refactoring
	key := models.Key{
		Address:   models.EIP55Address(acct.Address.Hex()),
		IsFunding: isFunding,
		JSON: models.JSON{
			Result: gjson.ParseBytes(exportedJSON),
		},
	}
	if err = ks.insertKeyIfNotExists(key); err != nil {
		return acct, err
	}
	return acct, nil
}

// SignTx uses the unlocked account to sign the given transaction.
func (ks *KeyStore) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return ks.gethKeyStore.SignTx(account, tx, chainID)
}

// GetAccounts returns all accounts
func (ks *KeyStore) GetAccounts() []accounts.Account {
	return ks.gethKeyStore.Accounts()
}

// HasAccountWithAddress returns true if keystore has an account with the given address
func (ks *KeyStore) HasAccountWithAddress(address common.Address) bool {
	for _, acct := range ks.GetAccounts() {
		if acct.Address == address {
			return true
		}
	}
	return false
}

// GetAccountByAddress returns the account matching the address provided, or an error if it is missing
func (ks *KeyStore) GetAccountByAddress(address common.Address) (accounts.Account, error) {
	for _, account := range ks.GetAccounts() {
		if account.Address == address {
			return account, nil
		}
	}
	return accounts.Account{}, errors.New("no account found with that address")
}

// ImportKey adds a new key to the keystore (writing to disk) and inserts to DB
func (ks *KeyStore) ImportKey(keyJSON []byte, oldPassword string) (acct accounts.Account, err error) {
	if ks.password == "" {
		return acct, ErrKeyStoreLocked
	}
	acct, err = ks.gethKeyStore.Import(keyJSON, oldPassword, ks.password)
	if err != nil {
		return acct, errors.Wrap(err, "could not import ETH key")
	}
	err = ks.gethKeyStore.Unlock(acct, ks.password)
	if err != nil {
		return acct, err
	}
	err = ks.SyncDiskKeyStoreToDB()
	if err != nil {
		return acct, err
	}
	return acct, nil
}

// Export exports as a JSON key, encrypted with newPassword
func (ks *KeyStore) Export(address common.Address, newPassword string) ([]byte, error) {
	if ks.password == "" {
		return nil, ErrKeyStoreLocked
	}
	acct, err := ks.GetAccountByAddress(address)
	if err != nil {
		return nil, errors.Wrap(err, "could not export ETH key")
	}
	return ks.gethKeyStore.Export(acct, ks.password, newPassword)
}

// DeleteKey hard-deletes a key whose address matches the supplied address.
func (ks *KeyStore) DeleteKey(address common.Address) error {
	if ks.password == "" {
		return ErrKeyStoreLocked
	}
	acct, err := ks.GetAccountByAddress(address)
	if err != nil {
		return err
	}
	return postgres.GormTransactionWithDefaultContext(ks.db, func(tx *gorm.DB) error {
		err := tx.Where("address = ?", address).Delete(&models.Key{}).Error
		if err != nil {
			return errors.Wrap(err, "while deleting ETH key from DB")
		}
		return ks.gethKeyStore.Delete(acct, ks.password)
	})
}

// ArchiveKey soft-deletes a key whose address matches the supplied address.
func (ks *KeyStore) ArchiveKey(address common.Address) error {
	if ks.password == "" {
		return ErrKeyStoreLocked
	}
	err := ks.db.Where("address = ?", address).Delete(&models.Key{}).Error
	if err != nil {
		return err
	}

	acct, err := ks.GetAccountByAddress(address)
	if err != nil {
		return err
	}

	// TODO: Is this correct?
	archivedKeysDir := filepath.Join(ks.keyDir, "archivedkeys")
	err = utils.EnsureDirAndMaxPerms(archivedKeysDir, os.FileMode(0700))
	if err != nil {
		return errors.Wrap(err, "could not create "+archivedKeysDir)
	}

	basename := filepath.Base(acct.URL.Path)
	dst := filepath.Join(archivedKeysDir, basename)
	err = utils.CopyFileWithMaxPerms(acct.URL.Path, dst, os.FileMode(0700))
	if err != nil {
		return errors.Wrap(err, "could not copy "+acct.URL.Path+" to "+dst)
	}

	return ks.gethKeyStore.Delete(acct, ks.password)
}

// UnlockedKeys returns all keys
func (ks *KeyStore) UnlockedKeys() ([]models.Key, error) {
	if ks.password == "" {
		return nil, ErrKeyStoreLocked
	}
	return ks.keys, nil
}

// SendKeys will return only the keys that are is_funding=false
func (ks *KeyStore) SendKeys() (keys []models.Key, err error) {
	if ks.password == "" {
		return nil, ErrKeyStoreLocked
	}
	for _, k := range ks.keys {
		if !k.IsFunding {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// FundingKeys will return only the keys that are is_funding=true
func (ks *KeyStore) FundingKeys() (keys []models.Key, err error) {
	if ks.password == "" {
		return nil, ErrKeyStoreLocked
	}
	for _, k := range ks.keys {
		if k.IsFunding {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// KeyByAddress returns the key matching provided address
func (ks *KeyStore) KeyByAddress(address common.Address) (models.Key, error) {
	if ks.password == "" {
		return models.Key{}, ErrKeyStoreLocked
	}
	for _, k := range ks.keys {
		if k.Address.Address() == address {
			return k, nil
		}
	}
	return models.Key{}, errors.Errorf("no key matching address %s", address.Hex())
}

// GetRoundRobinAddress gets the address of the "next" available key.
// This takes an optional param for a slice of addresses it should pick from. Leave empty to pick from all
// addresses in the database.
// FIXME: This can probably be done in memory for a big performance improvement
// if we don't care about crash-resistance or horizontal scaling
func (ks *KeyStore) GetRoundRobinAddress(db *gorm.DB, addresses ...common.Address) (address common.Address, err error) {
	if ks.password == "" {
		return common.Address{}, ErrKeyStoreLocked
	}
	err = postgres.GormTransactionWithoutContext(ks.db, func(tx *gorm.DB) error {
		q := tx.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Order("last_used ASC NULLS FIRST, id ASC")
		q = q.Where("is_funding = FALSE")
		if len(addresses) > 0 {
			q = q.Where("address in (?)", addresses)
		}
		keys := make([]models.Key, 0)
		err = q.Find(&keys).Error
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return errors.New("no keys available")
		}
		leastRecentlyUsedKey := keys[0]
		address = leastRecentlyUsedKey.Address.Address()
		return tx.Model(&leastRecentlyUsedKey).Update("last_used", time.Now()).Error
	})
	return address, err
}

// loadDBKeys returns a map of all of the keys saved in the database
// including the funding key.
func (ks *KeyStore) loadDBKeys() (keyMap map[common.Address]models.Key, err error) {
	var keys []models.Key
	err = ks.db.Order("created_at ASC, address ASC").Find(&keys).Error
	if err != nil {
		return nil, errors.Wrap(err, "failed to load keys")
	}
	keyMap = make(map[common.Address]models.Key)
	for _, k := range keys {
		keyMap[k.Address.Address()] = k
	}
	return keyMap, nil
}

// SyncDiskKeyStoreToDB reads all keys from the filesystem and insert into the DB.
// Due to how the underlying geth keystore works, we have to go via the
// filesystem rather than getting the key directly from memory
// TODO: Remove this entirely, should use Import on a running node via remote command to add a key
// See: https://app.clubhouse.io/chainlinklabs/story/9963/keystore-bptxm-refactoring
func (ks *KeyStore) SyncDiskKeyStoreToDB() error {
	files, err := utils.FilesInDir(ks.keyDir)
	if err != nil {
		return multierr.Append(errors.New("unable to sync disk keystore to db"), err)
	}

	var merr error
	for _, f := range files {
		key, err := models.NewKeyFromFile(filepath.Join(ks.keyDir, f))
		if err != nil {
			merr = multierr.Append(err, merr)
			continue
		}

		err = ks.insertKeyIfNotExists(key)
		if err != nil {
			merr = multierr.Append(err, merr)
		}
	}
	return merr
}

// insertKeyIfNotExists inserts a key if a key with that address doesn't exist already
// If a key with this address exists, it does nothing
func (ks *KeyStore) insertKeyIfNotExists(k models.Key) error {
	err := ks.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "address"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"deleted_at": nil}),
	}).Create(&k).Error
	if err == nil || err.Error() == "sql: no rows in result set" {
		return nil
	}
	return err
}

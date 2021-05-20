package health

import (
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/logger"
)

type Checkable interface {
	Ready() error
	Healthy() error
}

//go:generate mockery --name Checker --output ../../internal/mocks/ --case=underscore
type (
	Checker interface {
		Register(name string, service Checkable) error
		Unregister(name string) error
		IsReady() (ready bool, errors map[string]error)
		IsHealthy() (healthy bool, errors map[string]error)

		Start() error
		Close() error
	}

	checker struct {
		srvMutex   sync.RWMutex
		services   map[string]Checkable
		state      map[string]State
		stateMutex sync.RWMutex
		done       chan bool
	}

	State struct {
		ready   error
		healthy error
	}

	Status string
)

const (
	StatusPassing Status = "passing"
	StatusFailing Status = "failing"

	interval = 15 * time.Second
)

func NewChecker() Checker {
	c := &checker{
		services: make(map[string]Checkable, 10),
		state:    make(map[string]State, 10),
	}

	return c
}

func (c *checker) Start() error {
	go c.run()

	return nil
}

func (c *checker) Close() error {
	return nil
}

func (c *checker) run() {
	// update immediately
	c.update()

	ticker := time.Tick(interval)

	for {
		select {
		case <-ticker:
			c.update()
		case <-c.done:
			return
		}
	}

}

func (c *checker) update() {
	state := make(map[string]State, len(c.services))

	c.srvMutex.Lock()

	for name, s := range c.services {
		ready := s.Ready()
		healthy := s.Healthy()

		state[name] = State{ready, healthy}
	}

	c.srvMutex.Unlock()

	// we use a separate lock to avoid holding the lock while talking to services
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	for name, state := range state {
		c.state[name] = state
	}
}

func (c *checker) Register(name string, service Checkable) error {
	if service == nil || name == "" {
		return errors.Errorf("misconfigured check %v", service)
	}

	c.srvMutex.Lock()
	defer c.srvMutex.Unlock()
	c.services[name] = service
	return nil
}

func (c *checker) Unregister(name string) error {
	if name == "" {
		return errors.Errorf("name cannot be empty")
	}

	c.srvMutex.Lock()
	defer c.srvMutex.Unlock()
	c.services[name] = nil
	return nil
}

func (c *checker) IsReady() (ready bool, errors map[string]error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	ready = true
	errors = make(map[string]error, len(c.services))

	for name, state := range c.state {
		errors[name] = state.ready

		if state.ready != nil {
			ready = false
		}
	}

	return
}

func (c *checker) IsHealthy() (healthy bool, errors map[string]error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	healthy = true
	errors = make(map[string]error, len(c.services))

	for name, state := range c.state {
		errors[name] = state.healthy

		if state.healthy != nil {
			healthy = false
		}
	}

	return
}

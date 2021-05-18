package health

import (
	"sync"

	"github.com/pkg/errors"
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
	}

	checker struct {
		mutex    sync.RWMutex
		services map[string]Checkable
	}

	Status string
)

const (
	StatusPassing Status = "passing"
	StatusFailing Status = "failing"
)

func NewChecker() Checker {
	c := &checker{
		services: make(map[string]Checkable, 10),
	}

	return c
}

func (c *checker) Register(name string, service Checkable) error {
	if service == nil || name == "" {
		return errors.Errorf("misconfigured check %v", service)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.services[name] = service
	return nil
}

func (c *checker) Unregister(name string) error {
	if name == "" {
		return errors.Errorf("name cannot be empty")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.services[name] = nil
	return nil
}

func (c *checker) IsReady() (ready bool, errors map[string]error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	ready = true
	errors = make(map[string]error, len(c.services))

	for name, s := range c.services {
		err := s.Ready()
		errors[name] = err

		if err != nil {
			ready = false
		}
	}

	return
}

func (c *checker) IsHealthy() (healthy bool, errors map[string]error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	healthy = true
	errors = make(map[string]error, len(c.services))

	for name, s := range c.services {
		err := s.Healthy()
		errors[name] = err

		if err != nil {
			healthy = false
		}
	}

	return
}

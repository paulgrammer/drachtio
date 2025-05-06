package drachtio

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

// UserCredentials holds authentication information for a user
type UserCredentials struct {
	Username string
	Password string
}

type RegistryEvent int

const (
	AfterRegistrationEvent RegistryEvent = iota
)

type RegistryObserverFunc func(registration *Registration)

// Registry provides a simple implementation of Registry
type Registry struct {
	credentials   sync.Map // username -> UserCredentials
	registrations sync.Map // AOR -> *Registration
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	started       bool

	observers map[RegistryEvent][]RegistryObserverFunc
}

// NewRegistry creates a new registration handler
func NewRegistry() *Registry {
	return &Registry{
		observers: make(map[RegistryEvent][]RegistryObserverFunc),
	}
}

func (h *Registry) addObserver(event RegistryEvent, observer RegistryObserverFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.observers[event] = append(h.observers[event], observer)
}

func (h *Registry) notifyObservers(event RegistryEvent, reg *Registration) {
	observers := h.observers[event]
	for _, observer := range observers {
		observer(reg)
	}
}

func (h *Registry) OnRegistration(fn func(*Registration)) {
	h.addObserver(AfterRegistrationEvent, func(reg *Registration) { fn(reg) })
}

// AddUser adds a user's credentials to the handler
func (h *Registry) AddUser(username, password string) {
	h.credentials.Store(username, UserCredentials{
		Username: username,
		Password: password,
	})
}

// DeleteUser removes a user's credentials and any associated registrations
func (h *Registry) DeleteUser(username string) error {
	// Remove credentials
	_, exists := h.credentials.Load(username)
	if !exists {
		return fmt.Errorf("user '%s' not found", username)
	}

	h.credentials.Delete(username)

	return nil
}

// PasswordLookup implements Registry.PasswordLookup
func (h *Registry) PasswordLookup(req *SrfRequest, username string) (string, error) {
	cred, exists := h.credentials.Load(username)
	if !exists {
		return "", fmt.Errorf("user '%s' not found", username)
	}

	return cred.(UserCredentials).Password, nil
}

// OnRegister implements Registry.OnRegister
func (h *Registry) OnRegister(req *SrfRequest, aor string, contacts []*sip.ContactHeader) error {
	// Determine expiration time
	expiresSecs := 3600 // Default to 1 hour
	if expiresHeader := req.GetHeader("Expires"); expiresHeader != "" {
		fmt.Sscanf(expiresHeader, "%d", &expiresSecs)
	} else if len(contacts) > 0 {
		if expiresParam, ok := contacts[0].Params.Get("expires"); ok {
			fmt.Sscanf(expiresParam, "%d", &expiresSecs)
		}
	}

	// Create or update registration
	reg := &Registration{
		AOR:       aor,
		Contacts:  contacts,
		ExpiresAt: time.Now().Add(time.Duration(expiresSecs) * time.Second),
	}

	// Store the registration
	h.registrations.Store(aor, reg)

	h.notifyObservers(AfterRegistrationEvent, reg)
	return nil
}

// OnUnRegister implements Registry.OnUnRegister
func (h *Registry) OnUnRegister(req *SrfRequest, aor string) error {
	// Check if registration exists
	_, exists := h.registrations.Load(aor)
	if !exists {
		return fmt.Errorf("no registration found for AOR: %s", aor)
	}

	// Remove registration
	h.registrations.Delete(aor)
	return nil
}

// RegistrationLookup returns the registration for a specific AOR
func (h *Registry) RegistrationLookup(aor string) (*Registration, error) {
	value, exists := h.registrations.Load(aor)
	if !exists {
		return nil, fmt.Errorf("no registration found for AOR: %s", aor)
	}

	registration, ok := value.(*Registration)
	if !ok {
		return nil, fmt.Errorf("invalid registration type for AOR: %s", aor)
	}

	return registration, nil
}

// GetRegistrations returns all active registrations
func (h *Registry) GetRegistrations() []*Registration {
	registrations := make([]*Registration, 0)

	h.registrations.Range(func(_, value interface{}) bool {
		reg := value.(*Registration)
		registrations = append(registrations, reg)
		return true
	})

	return registrations
}

// Run starts the expiration watcher in a background goroutine
func (h *Registry) Run(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started {
		return
	}

	h.ctx, h.cancel = context.WithCancel(ctx)
	h.started = true
	h.wg.Add(1)

	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				h.removeExpiredRegistrations()
			case <-h.ctx.Done():
				return
			}
		}
	}()
}

// Stop cancels the expiration watcher and waits for it to finish
func (h *Registry) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
		h.started = false
	}
	h.wg.Wait()
}

// removeExpiredRegistrations checks and cleans up expired registrations
func (h *Registry) removeExpiredRegistrations() {
	now := time.Now()
	var expired []string

	h.registrations.Range(func(key, value interface{}) bool {
		aor := key.(string)
		reg := value.(*Registration)
		if reg.ExpiresAt.Before(now) {
			expired = append(expired, aor)
		}
		return true
	})

	for _, aor := range expired {
		h.registrations.Delete(aor)
	}
}

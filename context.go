package drachtio

import (
	"sync"
)

// Key is the key that a Context returns itself for.
const ContextKey = "drachtio-context-key"

// Context is the main data sharing mechanism for drachtio.
// It allows passing variables between middleware and handlers,
// managing flow, and storing request-scoped data.
type Context struct {
	// This mutex protects keys map
	mu sync.RWMutex

	// keys is a key/value pair exclusively for the context of each request
	keys map[string]interface{}
}

// NewContext creates a new context instance
func NewContext() *Context {
	return &Context{
		keys: make(map[string]interface{}),
	}
}

// Set stores a new key/value pair exclusively for this context
func (c *Context) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = make(map[string]interface{})
	}

	c.keys[key] = value
}

// Get returns the value for the given key, ie: (value, true)
// If the value does not exist it returns (nil, false)
func (c *Context) Get(key string) (value interface{}, exists bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists = c.keys[key]
	return
}

// MustGet returns the value for the given key if it exists, otherwise it panics
func (c *Context) MustGet(key string) interface{} {
	if value, exists := c.Get(key); exists {
		return value
	}
	panic("Key \"" + key + "\" does not exist")
}

// GetString returns the value associated with the key as a string
func (c *Context) GetString(key string) (s string) {
	if val, ok := c.Get(key); ok && val != nil {
		s, _ = val.(string)
	}
	return
}

// GetBool returns the value associated with the key as a boolean
func (c *Context) GetBool(key string) (b bool) {
	if val, ok := c.Get(key); ok && val != nil {
		b, _ = val.(bool)
	}
	return
}

// GetInt returns the value associated with the key as an integer
func (c *Context) GetInt(key string) (i int) {
	if val, ok := c.Get(key); ok && val != nil {
		i, _ = val.(int)
	}
	return
}

// GetInt64 returns the value associated with the key as an integer
func (c *Context) GetInt64(key string) (i64 int64) {
	if val, ok := c.Get(key); ok && val != nil {
		i64, _ = val.(int64)
	}
	return
}

// Error attaches an error to the current context if tracking is desired
func (c *Context) Error(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return err
}

// Copy returns a copy of the current context that can be safely used outside the request's scope
// This is useful when the context needs to be passed to a goroutine
func (c *Context) Copy() *Context {
	cp := Context{}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.keys != nil {
		cp.keys = make(map[string]interface{}, len(c.keys))
		for k, v := range c.keys {
			cp.keys[k] = v
		}
	}

	return &cp
}

// Value returns the value associated with this context for key, or nil
// if no value is associated with key
func (c *Context) Value(key interface{}) interface{} {
	if key == ContextKey {
		return c
	}
	if keyAsString, ok := key.(string); ok {
		if val, exists := c.Get(keyAsString); exists {
			return val
		}
	}
	return nil
}

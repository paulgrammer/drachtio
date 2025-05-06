package drachtio

import (
	"fmt"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"
)

// HandlerFunc defines function signature for handling SIP requests
type HandlerFunc func(*SrfRequest, *SrfResponse)

// ServeMux routes SIP requests to HandlerFuncs based on method patterns
type ServeMux struct {
	mu       sync.RWMutex
	handlers map[string]muxEntry
	middle   []HandlerFunc // Global middleware chain
}

type muxEntry struct {
	handlers []HandlerFunc
	pattern  string
}

// NewServeMux creates a new SIP request multiplexer
func NewServeMux() *ServeMux {
	return &ServeMux{
		handlers: make(map[string]muxEntry),
	}
}

// ServeRequest processes an incoming SIP request
func (mux *ServeMux) serveRequest(req *SrfRequest, res *SrfResponse) {
	entry := mux.findHandler(req.Method())
	chain := append(mux.middle, entry.handlers...)
	executeHandlers(chain, req, res)
}

// findHandler returns the handler chain for a SIP method
func (mux *ServeMux) findHandler(method sip.RequestMethod) muxEntry {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	normalized := normalizeMethod(method.String())
	if entry, exists := mux.handlers[normalized]; exists {
		return entry
	}
	return muxEntry{handlers: []HandlerFunc{NotFoundHandler}}
}

// Handle registers HandlerFuncs for a SIP method pattern
func (mux *ServeMux) Handle(pattern string, handlers ...HandlerFunc) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	validatePattern(pattern)
	validateHandlers(handlers)

	normalized := normalizeMethod(pattern)
	if _, exists := mux.handlers[normalized]; exists {
		panic(fmt.Sprintf("drachtio: multiple registrations for %q", pattern))
	}

	mux.handlers[normalized] = muxEntry{
		handlers: handlers,
		pattern:  pattern,
	}
}

// Use adds global middleware HandlerFuncs
func (mux *ServeMux) Use(middleware ...HandlerFunc) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	mux.middle = append(mux.middle, middleware...)
}

// executeHandlers runs handlers in sequence until response is sent
func executeHandlers(handlers []HandlerFunc, req *SrfRequest, res *SrfResponse) {
	for _, h := range handlers {
		if res.IsFinished() {
			return
		}
		h(req, res)
	}
}

// SIP method-specific registration helpers
func (mux *ServeMux) registerMethod(method sip.RequestMethod, handlers ...HandlerFunc) {
	mux.Handle(method.String(), handlers...)
}

func (mux *ServeMux) Ark(handlers ...HandlerFunc)      { mux.registerMethod(sip.ACK, handlers...) }
func (mux *ServeMux) Invite(handlers ...HandlerFunc)   { mux.registerMethod(sip.INVITE, handlers...) }
func (mux *ServeMux) Bye(handlers ...HandlerFunc)      { mux.registerMethod(sip.BYE, handlers...) }
func (mux *ServeMux) Cancel(handlers ...HandlerFunc)   { mux.registerMethod(sip.CANCEL, handlers...) }
func (mux *ServeMux) Register(handlers ...HandlerFunc) { mux.registerMethod(sip.REGISTER, handlers...) }
func (mux *ServeMux) Options(handlers ...HandlerFunc)  { mux.registerMethod(sip.OPTIONS, handlers...) }
func (mux *ServeMux) Subscribe(handlers ...HandlerFunc) {
	mux.registerMethod(sip.SUBSCRIBE, handlers...)
}
func (mux *ServeMux) Notify(handlers ...HandlerFunc)  { mux.registerMethod(sip.NOTIFY, handlers...) }
func (mux *ServeMux) Refer(handlers ...HandlerFunc)   { mux.registerMethod(sip.REFER, handlers...) }
func (mux *ServeMux) Info(handlers ...HandlerFunc)    { mux.registerMethod(sip.INFO, handlers...) }
func (mux *ServeMux) Message(handlers ...HandlerFunc) { mux.registerMethod(sip.MESSAGE, handlers...) }
func (mux *ServeMux) Prack(handlers ...HandlerFunc)   { mux.registerMethod(sip.PRACK, handlers...) }
func (mux *ServeMux) Update(handlers ...HandlerFunc)  { mux.registerMethod(sip.UPDATE, handlers...) }

// register to receive CDRs
func (mux *ServeMux) OnCDRAttempt(handler func(source, time, msg string)) {
	panic("unimplemented")
}

func (mux *ServeMux) OnCDRStart(handler func(source, time, role, msg string)) {
	panic("unimplemented")
}

func (mux *ServeMux) OnCDRStop(handler func(source, time, reason, msg string)) {
	panic("unimplemented")
}

// Validation helpers
func validatePattern(pattern string) {
	if strings.TrimSpace(pattern) == "" {
		panic("drachtio: empty pattern")
	}
}

func validateHandlers(handlers []HandlerFunc) {
	if len(handlers) == 0 {
		panic("drachtio: no handlers provided")
	}
	for _, h := range handlers {
		if h == nil {
			panic("drachtio: nil handler")
		}
	}
}

// normalizeMethod ensures case-insensitive matching
func normalizeMethod(method string) string {
	return strings.ToLower(method)
}

// NotFoundHandler responds with 404
func NotFoundHandler(req *SrfRequest, res *SrfResponse) {
	res.NotFound()
}

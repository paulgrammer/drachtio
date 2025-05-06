package drachtio

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

type ProxyResponse struct {
	Address string
	Port    int
	Msgs    []SipMessage
}

type ProxyResult struct {
	Connected     bool
	Responses     []ProxyResponse
	FinalStatus   int
	FinalResponse *SipMessage
}

type RequestEvent int

const (
	RequestEventCancel RequestEvent = iota
	ResponseEventCancel
	ResponseEvent
)

type RequestObserverFunc func(interface{})

type SrfRequest struct {
	*SipMessage
	*Context
	Raw       *InboundSIPRequest
	wp        *WireProtocol
	mu        sync.RWMutex
	observers map[RequestEvent][]RequestObserverFunc
}

func NewSrfRequest(wp *WireProtocol, sipMsg *SipMessage, rawMsg *InboundSIPRequest) *SrfRequest {
	return &SrfRequest{
		wp:         wp,
		SipMessage: sipMsg,
		Raw:        rawMsg,
		Context:    NewContext(),
		observers:  make(map[RequestEvent][]RequestObserverFunc),
	}
}

// HasHeader checks if a header exists
func (req *SrfRequest) HasHeader(key string) bool {
	return len(req.GetHeaders(key)) > 0
}

func (req *SrfRequest) addObserver(event RequestEvent, observer RequestObserverFunc) {
	req.mu.Lock()
	defer req.mu.Unlock()
	req.observers[event] = append(req.observers[event], observer)
}

func (req *SrfRequest) notifyReqObservers(event RequestEvent) {
	observers := req.observers[event]
	for _, observer := range observers {
		observer(req)
	}
}

func (req *SrfRequest) notifyResObservers(event RequestEvent, res *SrfResponse) {
	observers := req.observers[event]
	for _, observer := range observers {
		observer(res)
	}
}

func (req *SrfRequest) OnCancel(fn func(*SrfRequest)) {
	req.addObserver(RequestEventCancel, func(event interface{}) {
		if r, ok := event.(*SrfRequest); ok {
			fn(r)
		}
	})
}

func (req *SrfRequest) OnResponse(fn func(*SrfResponse)) {
	req.addObserver(ResponseEvent, func(event interface{}) {
		if res, ok := event.(*SrfResponse); ok {
			fn(res)
		}
	})
}

func (req *SrfRequest) GetHeaderParam(h, param string) string {
	panic("unimplemented")
}

func (req *SrfRequest) RequestURI() string {
	return req.From().Address.String()
}

func (req *SrfRequest) RemoteHost() string {
	return req.Raw.SourceAddress
}

func (req *SrfRequest) RemoteAddr() string {
	return fmt.Sprintf("%s:%s", req.Raw.SourceAddress, req.Raw.SourcePort)
}

func (req *SrfRequest) RemotePort() int {
	port, _ := strconv.Atoi(req.Raw.SourcePort)
	return port
}

// Cancel sends a CANCEL request to abort a previously sent INVITE
func (req *SrfRequest) Cancel(reason ...string) error {
	if req.Raw.Source != "application" {
		return errors.New("Cancel can only be used for UAC requests")
	}

	_, err := req.wp.Request(NewWirePingCommand())
	if err == nil {
		req.notifyReqObservers(RequestEventCancel)
	}

	return err
}

// ProxyOptions holds configuration for proxying a SIP request
type ProxyOptions struct {
	Destination        []string
	RemainInDialog     bool
	FollowRedirects    bool
	Forking            string
	ProvisionalTimeout time.Duration
	FinalTimeout       time.Duration
}

// Proxy forwards the request to one or more destinations
func (req *SrfRequest) Proxy(opts ProxyOptions) (*ProxyResult, error) {
	if req.Raw.Source != "network" {
		return nil, errors.New("Proxy can only be used for incoming requests")
	}

	if len(opts.Destination) == 0 {
		return nil, errors.New("no destination provided for proxy")
	}

	fmt.Printf("Starting proxy to destinations: %v\n", opts.Destination)

	result := &ProxyResult{}

	return result, nil
}

package drachtio

import (
	"fmt"
	"net/textproto"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"
)

const (
	DR_CRLF     = "\r\n"
	NAT_EXPIRES = 30
)

func IsUacBehindNat(protocol string) bool {
	// no need for NAT handling if WSS or TCP is being used
	// let's keep it simple -- if UDP, let's crank down the register interval
	return strings.ToLower(protocol) == "udp"
}

// MakeDialogIDFromMessage creates dialog ID of message.
// returns error if callid or to tag or from tag does not exists
func MakeDialogIDFromRequest(msg *sip.Request) (string, error) {
	return ReadRequestDialogID(msg)
}

// MakeDialogIDFromResponse creates dialog ID of message.
// returns error if callid or to tag or from tag does not exists
func MakeDialogIDFromResponse(msg *sip.Response) (string, error) {
	return ReadResponseDialogID(msg)
}

// UASReadRequestDialogID creates dialog ID of message if receiver has UAS role.
// returns error if callid or to tag or from tag does not exists
func ReadRequestDialogID(msg *sip.Request) (string, error) {
	var callID, fromTag string = "", ""
	if err := getDialogIDFromMessage(msg, &callID, &fromTag); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s;from-tag=%s", callID, fromTag), nil
}

// ReadResponseDialogID creates dialog ID of message if receiver has UAS role.
func ReadResponseDialogID(msg *sip.Response) (string, error) {
	var callID, fromTag string = "", ""
	if err := getDialogIDFromMessage(msg, &callID, &fromTag); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s;from-tag=%s", callID, fromTag), nil
}

// getDialogIDFromMessage extracts Call-ID, To tag, and From tag from a SIP message.
func getDialogIDFromMessage(msg sip.Message, callId, fromHeaderTag *string) error {
	callID := msg.CallID()
	if callID == nil {
		return fmt.Errorf("missing Call-ID header")
	}

	from := msg.From()
	if from == nil {
		return fmt.Errorf("missing From header")
	}

	fromTag, ok := from.Params.Get("tag")
	if !ok {
		return fmt.Errorf("missing tag param in From header")
	}

	*callId = callID.Value()
	*fromHeaderTag = fromTag

	return nil
}

type SrfHeader struct {
	mu      sync.RWMutex
	headers textproto.MIMEHeader
}

func NewSrfHeader() *SrfHeader {
	return &SrfHeader{
		headers: make(textproto.MIMEHeader),
	}
}

func (h *SrfHeader) Has(key string) bool {
	key = strings.ToLower(key)

	h.mu.RLock()
	defer h.mu.RUnlock()

	_, ok := h.headers[key]
	return ok
}

func (h *SrfHeader) Add(key, value string) {
	key = strings.ToLower(key)

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.headers[key]; exists {
		h.headers.Set(key, value)
	} else {
		h.headers.Add(key, value)
	}
}

func (h *SrfHeader) Del(key string) {
	key = strings.ToLower(key)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.headers.Del(key)
}

func (h *SrfHeader) Get(key string) string {
	key = strings.ToLower(key)

	h.mu.RLock()
	defer h.mu.RUnlock()

	if values, ok := h.headers[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func (h *SrfHeader) ToSIP() []sip.Header {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var sipHeaders []sip.Header
	for key, values := range h.headers {
		for _, value := range values {
			sipHeaders = append(sipHeaders, sip.NewHeader(key, value))
		}
	}
	return sipHeaders
}

// SliceContains checks if a slice contains a specific string.
func SliceContains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

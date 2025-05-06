package drachtio

import (
	"net/textproto"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// SipMessage represents a SIP request or response
type SipMessage struct {
	sip.Message
}

func NewSipMessage(body string) (*SipMessage, error) {
	parser := sip.NewParser()
	msg, err := parser.ParseSIP([]byte(body)) // too expensive operation
	if err != nil {
		return nil, err
	}

	return &SipMessage{Message: msg}, nil
}

// GetHeader returns the first value for the given header
func (m *SipMessage) GetHeader(key string) string {
	if req, ok := m.Message.(*sip.Request); ok {
		key = strings.ToLower(key)
		if header := req.GetHeader(key); header != nil {
			return header.Value()
		}
	}

	return ""
}

func (m *SipMessage) Type() string {
	_, ok := m.Message.(*sip.Request)
	if ok {
		return "request"
	}

	return "response"
}

func (m *SipMessage) Method() sip.RequestMethod {
	req, ok := m.Message.(*sip.Request)
	if ok {
		return req.Method
	}

	return sip.RequestMethod("UNKNOWN")
}

// AddHeader adds a header value
func (m *SipMessage) AddHeader(key, value string) {
	header := sip.NewHeader(normalizeHeaderName(key), value)
	m.AppendHeader(header)
}

// CalledNumber returns the user part of the request URI
func (m *SipMessage) CalledNumber() string {
	user := m.To().Address.User
	if idx := strings.Index(user, ";"); idx != -1 {
		user = user[:idx]
	}
	return user
}

// CallingNumber returns the user part from P-Asserted-Identity or From header
func (m *SipMessage) CallingNumber() string {
	user := m.From().Address.User
	if idx := strings.Index(user, ";"); idx != -1 {
		user = user[:idx]
	}
	return user
}

// CallingName returns the display name from P-Asserted-Identity or From header
func (m *SipMessage) CallingName() string {
	return m.From().DisplayName
}

// CanFormDialog checks if the message can form a dialog
func (m *SipMessage) CanFormDialog() bool {
	return m.CSeq().MethodName == sip.INVITE || m.CSeq().MethodName == sip.SUBSCRIBE
}

func normalizeHeaderName(key string) string {
	key = strings.ToLower(key)

	return textproto.CanonicalMIMEHeaderKey(key)
}

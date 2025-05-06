package drachtio

import "github.com/emiago/sipgo/sip"

// configuration options for the proxy operation
type ProxyRequestOptions struct{}

// RequestOptions contains options for sending requests within a dialog
type RequestOptions struct {
	URI     string
	Method  sip.RequestMethod
	Headers map[string]string
	Body    string
	Auth    *AuthCredentials
	Proxy   string
	NoAck   bool // Used for re-INVITE - if set to true, don't automatically send ACK
}

// AuthCredentials contains authentication credentials
type AuthCredentials struct {
	Username string
	Password string
}

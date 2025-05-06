package drachtio

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

// Registration represents a SIP client registration
type Registration struct {
	AOR       string               // Address of Record
	Contacts  []*sip.ContactHeader // Registered contacts
	ExpiresAt time.Time            // When this registration expires
}

// RegistryHandler defines interface for handling registration events
type RegistryType interface {
	PasswordLookup(req *SrfRequest, username string) (string, error)
	OnRegister(req *SrfRequest, aor string, contacts []*sip.ContactHeader) error
	OnUnRegister(req *SrfRequest, aor string) error
	RegistrationLookup(aor string) (*Registration, error)
}

type DigestAuthOptions struct {
	Realm         string
	Opaque        string
	Algorithm     string
	Secret        string
	NonceValidity time.Duration
}

type DigestAuth struct {
	opts     DigestAuthOptions
	registry RegistryType
}

// NewDigestAuth creates new authentication handler with options
func NewDigestAuth(registry RegistryType, opts ...func(*DigestAuthOptions)) *DigestAuth {
	options := DigestAuthOptions{
		Realm:         "drachtio",
		Algorithm:     "MD5",
		NonceValidity: 5 * time.Minute,
	}

	for _, opt := range opts {
		opt(&options)
	}

	if options.Secret == "" {
		panic("Auth secret must be provided")
	}

	return &DigestAuth{
		registry: registry,
		opts:     options,
	}
}

func (a *DigestAuth) Serve(req *SrfRequest, res *SrfResponse) {
	if isValid := a.handleChallengeFlow(req, res); !isValid {
		return
	}

	contactHeaders := req.GetHeaders("Contact")
	if len(contactHeaders) == 0 {
		res.BadRequest("Contact header is required for REGISTER requests")
		return
	}

	contactHeader, ok := contactHeaders[0].(*sip.ContactHeader)
	if !ok {
		res.BadRequest("Invalid Contact header")
		return
	}

	contact, expires := a.processContact(req, contactHeader)
	aor := req.From().Address.String()

	if expires > 0 {
		if err := a.registry.OnRegister(req, aor, []*sip.ContactHeader{contactHeader}); err != nil {
			res.InternalServerError(err.Error())
			return
		}
	} else {
		if err := a.registry.OnUnRegister(req, aor); err != nil {
			res.InternalServerError(err.Error())
			return
		}
	}

	res.WithHeader("Contact", contact.Address.String())
	res.WithHeader("Expires", strconv.Itoa(expires))
	res.Ok()
}

func (a *DigestAuth) handleChallengeFlow(req *SrfRequest, res *SrfResponse) bool {
	authHeader := req.GetHeader("Authorization")
	if authHeader == "" {
		a.sendChallenge(req, res)
		return false
	}

	return a.validateRequest(authHeader, req, res)
}

func (a *DigestAuth) sendChallenge(req *SrfRequest, res *SrfResponse) {
	chal := digest.Challenge{
		Realm:     a.opts.Realm,
		Opaque:    a.opts.Opaque,
		Algorithm: a.opts.Algorithm,
		Nonce:     a.generateNonce(req.RemoteAddr()),
	}
	res.WithHeader("WWW-Authenticate", chal.String())
	res.Unauthorized()
}

func (a *DigestAuth) generateNonce(remoteAddr string) string {
	host, port, _ := net.SplitHostPort(remoteAddr)
	timestamp := time.Now().UnixMicro()
	data := fmt.Sprintf("%d:%s:%s", timestamp, host, port)
	return fmt.Sprintf("%s:%s", data, a.hmacSignature(data))
}

func (a *DigestAuth) validateRequest(authHeader string, req *SrfRequest, res *SrfResponse) bool {
	cred, err := digest.ParseCredentials(authHeader)
	if err != nil {
		res.Unauthorized("Invalid authorization header")
		return false
	}

	if !a.validateNonce(cred.Nonce, req.RemoteAddr()) {
		res.Unauthorized("Invalid nonce")
		return false
	}

	password, err := a.registry.PasswordLookup(req, cred.Username)
	if err != nil {
		res.NotFound("User not found")
		return false
	}

	if !a.validateDigest(cred, password) {
		res.Unauthorized("Invalid credentials")
		return false
	}

	return true
}

func (a *DigestAuth) validateNonce(nonce, remoteAddr string) bool {
	parts := strings.Split(nonce, ":")
	if len(parts) != 4 {
		return false
	}

	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Since(time.UnixMicro(timestamp)) > a.opts.NonceValidity {
		return false
	}

	hostPort := fmt.Sprintf("%s:%s", parts[1], parts[2])
	if hostPort != remoteAddr {
		return false
	}

	data := strings.Join(parts[:3], ":")
	return hmac.Equal([]byte(parts[3]), []byte(a.hmacSignature(data)))
}

func (a *DigestAuth) validateDigest(cred *digest.Credentials, password string) bool {
	chal := digest.Challenge{
		Realm:     a.opts.Realm,
		Nonce:     cred.Nonce,
		Opaque:    a.opts.Opaque,
		Algorithm: a.opts.Algorithm,
	}

	digCred, err := digest.Digest(&chal, digest.Options{
		URI:      cred.URI,
		Password: password,
		Username: cred.Username,
		Method:   sip.REGISTER.String(),
	})

	return err == nil && digCred.Response == cred.Response
}

func (a *DigestAuth) processContact(req *SrfRequest, contact *sip.ContactHeader) (*sip.ContactHeader, int) {
	expires := parseExpires(contact)
	contact = contact.Clone()

	if IsUacBehindNat(req.Transport()) {
		contact.Address.Host = req.RemoteHost()
		contact.Address.Port = req.RemotePort()
		expires = NAT_EXPIRES
	}

	return contact, expires
}

func (a *DigestAuth) hmacSignature(data string) string {
	mac := hmac.New(sha256.New, []byte(a.opts.Secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// Helper functions
func parseExpires(contact *sip.ContactHeader) int {
	if expires, ok := contact.Params.Get("expires"); ok {
		if val, err := strconv.Atoi(expires); err == nil {
			return val
		}
	}
	return 0
}

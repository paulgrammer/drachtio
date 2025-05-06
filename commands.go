package drachtio

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type WireCommand interface {
	String() string
}

type WireAuthenticateCommand struct {
	secret string
	tags   []string
}

// NewWireAuthenticateCommand creates a new authentication command.
// It requires a secret and accepts optional tags.
func NewWireAuthenticateCommand(secret string, tags ...string) *WireAuthenticateCommand {
	return &WireAuthenticateCommand{secret, tags}
}

func (c *WireAuthenticateCommand) String() string {
	return fmt.Sprintf("%s|%s|%s", c.Name(), c.secret, strings.Join(c.tags, ","))
}

func (c *WireAuthenticateCommand) Name() string {
	return "authenticate"
}

// WireRouteCommand represents the route registration command.
type WireRouteCommand struct {
	method string
}

func NewWireRouteCommand(method string) *WireRouteCommand {
	return &WireRouteCommand{method: method}
}

func (c *WireRouteCommand) String() string {
	return fmt.Sprintf("%s|%s", c.Name(), c.method)
}

func (c *WireRouteCommand) Name() string {
	return "route"
}

// WireSIPCommand represents a SIP response sent to the server.
type WireSIPCommand struct {
	transactionID string
	dialogID      string
	proxy         string
	sipMessage    string
}

type SIPCommandOption func(*WireSIPCommand)

func NewWireSIPCommand(sipMessage string, opts ...SIPCommandOption) *WireSIPCommand {
	cmd := &WireSIPCommand{
		sipMessage: sipMessage,
	}
	for _, opt := range opts {
		opt(cmd)
	}
	return cmd
}

func (c *WireSIPCommand) String() string {
	parts := []string{c.Name(), c.transactionID, c.dialogID}

	// Append Proxy only if it's set
	if c.proxy != "" {
		parts = append(parts, c.proxy)
	}

	return fmt.Sprintf("%s%s%s", strings.Join(parts, "|"), DR_CRLF, c.sipMessage)
}

func (c *WireSIPCommand) Name() string {
	return "sip"
}

// WirePingCommand represents a ping command to check server connectivity.
type WirePingCommand struct{}

func NewWirePingCommand() *WirePingCommand {
	return &WirePingCommand{}
}

func (c *WirePingCommand) String() string {
	return "ping"
}

func NewWireMessage(cmd WireCommand) (string, string) {
	reqID := uuid.New().String()
	payload := fmt.Sprintf("%d#%s|%s", len(reqID)+1+len(cmd.String()), reqID, cmd.String())

	return reqID, payload
}

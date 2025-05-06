package drachtio

import (
	"fmt"
	"net"
	"time"
)

const (
	defaultReconnectInitial  = 5 * time.Second
	defaultReconnectMax      = 30 * time.Second
	defaultPingInterval      = 15 * time.Second
	defaultPingFailThreshold = 3
	minPingInterval          = 5 * time.Second
	maxPingInterval          = 5 * time.Minute
)

type ConnectionOptions struct {
	Host              string
	Port              int
	Secret            string
	Tags              []string
	Reconnect         bool
	ReconnectInitial  time.Duration
	ReconnectMax      time.Duration
	PingInterval      time.Duration
	PingFailThreshold int
}

func (o *ConnectionOptions) Validate() error {
	if o.PingInterval < minPingInterval || o.PingInterval > maxPingInterval {
		return fmt.Errorf("ping interval must be between %s and %s",
			minPingInterval, maxPingInterval)
	}
	return nil
}

func (o *ConnectionOptions) ApplyDefaults() {
	if o.ReconnectInitial == 0 {
		o.ReconnectInitial = defaultReconnectInitial
	}
	if o.ReconnectMax == 0 {
		o.ReconnectMax = defaultReconnectMax
	}
	if o.PingInterval == 0 {
		o.PingInterval = defaultPingInterval
	}
	if o.PingFailThreshold == 0 {
		o.PingFailThreshold = defaultPingFailThreshold
	}
}

type ConnectionHandler interface {
	OnConnect(net.Conn)
	OnDisconnect(net.Conn)
	OnMessage(WireResponse)
	OnError(error)
}

package drachtio

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrNotConnected = fmt.Errorf("not connected")
)

type WireResponse interface{}

type WireProtocol struct {
	logger    *slog.Logger
	conn      net.Conn
	options   ConnectionOptions
	handler   ConnectionHandler
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	callbacks *callbackManager
	msgParser *messageParser
}

func NewWireProtocol(handler ConnectionHandler, logger *slog.Logger) *WireProtocol {
	return &WireProtocol{
		logger:    logger,
		handler:   handler,
		callbacks: newCallbackManager(),
		msgParser: newMessageParser(logger),
	}
}

func (p *WireProtocol) Connect(ctx context.Context, opts ConnectionOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	opts.ApplyDefaults()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.options = opts
	p.ctx, p.cancel = context.WithCancel(ctx)

	p.wg.Add(1)
	go p.connectionManager()

	return nil
}

func (p *WireProtocol) connectionManager() {
	defer p.wg.Done()

	var backoff time.Duration
	attempt := 0

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			conn, err := net.Dial("tcp", net.JoinHostPort(p.options.Host, strconv.Itoa(p.options.Port)))
			if err != nil {
				attempt++
				backoff = p.calculateBackoff(attempt)
				p.logger.Warn("Connection failed", 
					"error", err,
					"backoff", backoff)

				select {
				case <-time.After(backoff):
				case <-p.ctx.Done():
					return
				}
				continue
			}

			p.setConnection(conn)

			go p.handler.OnConnect(conn)
			attempt = 0

			connCtx, cancel := context.WithCancel(p.ctx)
			// Add wait group entries for both goroutines
			p.wg.Add(2)

			go p.readLoop(connCtx, cancel)
			go p.pingMonitor(connCtx, cancel)

			select {
			case <-connCtx.Done():
				p.logger.Debug("Connection terminated")
				cancel()
				p.handler.OnDisconnect(conn)
				// Continue the loop to allow reconnection
				continue
			case <-p.ctx.Done():
				cancel()
				conn.Close()
				return
			}
		}
	}
}

func (p *WireProtocol) setConnection(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conn = conn
}

func (p *WireProtocol) readLoop(ctx context.Context, cancel context.CancelFunc) {
	defer p.wg.Done()
	defer cancel()

	reader := bufio.NewReader(p.conn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := p.msgParser.Read(reader)
			if err != nil {
				p.handler.OnError(err)
				return
			}

			p.wg.Add(1)
			go func() {
				defer p.wg.Done()

				if resp := p.callbacks.Handle(msg); resp == nil {
					p.handler.OnMessage(msg)
				}
			}()
		}
	}
}

func (p *WireProtocol) pingMonitor(ctx context.Context, cancel context.CancelFunc) {
	defer p.wg.Done()
	defer cancel()

	ticker := time.NewTicker(p.options.PingInterval)
	defer ticker.Stop()

	failures := 0
	for {
		select {
		case <-ticker.C:
			if err := p.sendPing(); err != nil {
				failures++
				if failures >= p.options.PingFailThreshold {
					p.logger.Error("Ping failure threshold reached")
					return
				}
			} else {
				failures = 0
			}
		case <-ctx.Done():
			return
		}
	}
}

func (p *WireProtocol) sendPing() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.RequestAsync(ctx, NewWirePingCommand())
	return err
}

func (p *WireProtocol) calculateBackoff(attempt int) time.Duration {
	if !p.options.Reconnect {
		return 0
	}

	backoff := p.options.ReconnectInitial * time.Duration(attempt)
	if backoff > p.options.ReconnectMax {
		backoff = p.options.ReconnectMax
	}
	return backoff
}

// Request sends an asynchronous request using the WireProtocol.
// It generates a unique request ID and payload for the given WireCommand,
// sends the request over the connection, and returns the request ID.
func (p *WireProtocol) Request(cmd WireCommand) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	reqID, payload := NewWireMessage(cmd)
	if p.conn == nil {
		p.logger.Error("Attempted to send request while not connected")
		return "", ErrNotConnected
	}

	if _, err := p.conn.Write([]byte(payload)); err != nil {
		p.logger.Error("Failed to send async request",
			"error", err,
			"reqID", reqID)
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	return reqID, nil
}

// RequestAsync sends a synchronous request using the WireProtocol and waits for a response.
// It generates a unique request ID and payload for the given WireCommand, sends the request
// over the connection, and waits for a response or context cancellation.
func (p *WireProtocol) RequestAsync(ctx context.Context, cmd WireCommand) (*InboundResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	reqID, payload := NewWireMessage(cmd)

	if p.conn == nil {
		p.logger.Error("Attempted to send sync request while not connected")
		return nil, ErrNotConnected
	}

	respCh := make(chan *InboundResponse, 1)
	p.callbacks.Register(reqID, respCh)
	defer p.callbacks.Unregister(reqID)

	if _, err := p.conn.Write([]byte(payload)); err != nil {
		p.logger.Error("Failed to send async request",
			"error", err,
			"reqID", reqID)

		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-respCh:
		return resp, nil
	}
}

func (p *WireProtocol) Disconnect() {
	p.cancel()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}
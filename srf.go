package drachtio

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

type Srf struct {
	*ServeMux
	*DialogHandler
	logger     *slog.Logger
	wp         *WireProtocol
	options    ConnectionOptions
	mu         sync.RWMutex
	localAddrs []string
	ctx        context.Context
}

func NewSrf(opts ...func(*ConnectionOptions)) *Srf {
	logOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	handler := slog.NewTextHandler(os.Stdout, logOpts)
	logger := slog.New(handler)

	options := ConnectionOptions{
		Reconnect:         true,
		ReconnectInitial:  defaultReconnectInitial,
		ReconnectMax:      defaultReconnectMax,
		PingInterval:      defaultPingInterval,
		PingFailThreshold: defaultPingFailThreshold,
	}

	for _, opt := range opts {
		opt(&options)
	}

	srf := &Srf{
		ServeMux: NewServeMux(),
		logger:   logger,
		options:  options,
	}

	srf.wp = NewWireProtocol(srf, logger)
	srf.DialogHandler = NewDialogHandler(srf.wp)

	return srf
}

func (s *Srf) ProxyRequest(req *SrfRequest, destination []string, opts *ProxyRequestOptions) {
	panic("unimplemented")
}

func (s *Srf) Request(destination string, opts *RequestOptions) {
	panic("unimplemented")
}

func (s *Srf) Connect(ctx context.Context) error {
	s.ctx = ctx
	return s.wp.Connect(ctx, s.options)
}

func (s *Srf) OnConnect(conn net.Conn) {
	if err := s.authenticate(); err != nil {
		s.logger.Error("Authentication failed", "error", err)
		return
	}

	s.logger.Info("Connected to a drachtio server", 
		"remote", conn.RemoteAddr().String(),
		"addresses", s.localAddrs)

	s.registerHandlers()
}

func (s *Srf) OnDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localAddrs = nil
	s.logger.Warn("Disconnected")
}

func (s *Srf) OnMessage(msg WireResponse) {
	switch v := msg.(type) {
	case *InboundSIPRequest:
		s.handleSIPMessage(v)
	case *InboundResponse:
		s.handleInboundResponse(v)
	case *IncomingCDREvent:
		s.handleCDREvent(v)
	}
}

func (s *Srf) OnError(err error) {
	s.logger.Error("Connection error", "error", err)
}

func (s *Srf) authenticate() error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	response, err := s.wp.RequestAsync(ctx, NewWireAuthenticateCommand(s.options.Secret, s.options.Tags...))
	if err != nil {
		return err
	}

	if response.Status != "OK" {
		return fmt.Errorf("authentication failed: %s", response.RawMsg)
	}

	s.localAddrs = strings.Split(response.Data[0], ",")
	return nil
}

func (s *Srf) registerHandlers() {
	for method := range s.ServeMux.handlers {
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()

		if _, err := s.wp.RequestAsync(ctx, NewWireRouteCommand(method)); err != nil {
			s.logger.Error("Failed to register route", "error", err, "method", method)
		}
	}
}

func (s *Srf) handleInboundResponse(resp *InboundResponse) {
	s.logger.Debug("Received inbound response",
		"status", resp.Status,
		"request-id", resp.RequestID,
		"message-id", resp.MessageID)
}

func (s *Srf) handleSIPMessage(msg *InboundSIPRequest) {
	sipMsg, err := NewSipMessage(msg.SIPMessage)
	if err != nil {
		s.logger.Error("Failed to parse SIP message", "error", err)
		return
	}

	if req, ok := sipMsg.Message.(*sip.Request); ok {
		// Create request and response objects
		request := NewSrfRequest(s.wp, sipMsg, msg)
		response := NewSrfResponse(s.wp, req, msg)

		// Store the transaction ID from the message for later use
		transactionID := msg.TransactionID

		// Store the dialog ID if present
		dialogID := msg.DialogID

		// Try to handle as in-dialog request
		if request.Method() != sip.REGISTER {
			if request.CallID() != nil && request.From() != nil && request.To() != nil {
				// Check for dialog-creating requests like INVITE, SUBSCRIBE
				// Dialog-creating requests with To-tag are always in-dialog requests
				if _, hasToTag := request.To().Params.Get("tag"); hasToTag {
					if s.serveDialog(request, response, dialogID, transactionID) {
						// Request was handled within dialog context
						s.logger.Debug("Handled in-dialog request",
							"method", string(request.Method()),
							"call-id", request.CallID().Value(),
							"dialog-id", dialogID,
							"transaction-id", transactionID)
						return
					}
				}

				// For non-dialog-creating requests like BYE, INFO, MESSAGE, etc.
				// they MUST have both From-tag and To-tag to be in-dialog
				if request.Method() != sip.INVITE && request.Method() != sip.SUBSCRIBE {
					_, hasFromTag := request.From().Params.Get("tag")
					_, hasToTag := request.To().Params.Get("tag")

					if hasFromTag && hasToTag {
						if s.serveDialog(request, response, dialogID, transactionID) {
							// Request was handled within dialog context
							s.logger.Debug("Handled in-dialog request",
								"method", string(request.Method()),
								"call-id", request.CallID().Value(),
								"dialog-id", dialogID,
								"transaction-id", transactionID)
							return
						}
					}
				}
			}
		}

		// Not an in-dialog request or no matching dialog found, use regular routing
		// Store the transaction ID in the request context for use in handlers
		request.Set("transaction-id", transactionID)
		if dialogID != "" {
			request.Set("dialog-id", dialogID)
		}

		s.serveRequest(request, response)
	} else if resp, ok := sipMsg.Message.(*sip.Response); ok {
		// Handle SIP responses
		// Particularly useful for handling responses to UAC dialogs
		s.handleSIPResponse(resp, msg)
	}
}

func (s *Srf) serveDialog(req *SrfRequest, res *SrfResponse, dialogID string, transactionID string) bool {
	var dialog *Dialog

	// If dialog ID is provided, try to find the dialog directly
	if dialogID != "" {
		dialog = s.DialogHandler.FindDialogById(dialogID)
	}

	// If no dialog found by ID, try to find by Call-ID and tags
	if dialog == nil {
		// Extract dialog information from request
		callID := req.CallID().Value()
		if callID == "" {
			return false
		}

		// Try to extract from and to tags for dialog identification
		fromHeader := req.From()
		toHeader := req.To()
		if fromHeader == nil || toHeader == nil {
			return false
		}

		fromTag, hasFromTag := fromHeader.Params.Get("tag")
		toTag, hasToTag := toHeader.Params.Get("tag")

		if !hasFromTag || !hasToTag {
			// One of the tags is missing, this might be an initial request
			return false
		}

		// Try to find dialog by Call-ID and tags
		dialog = s.DialogHandler.FindDialogByCallIDAndFromTag(callID, fromTag)
		if dialog == nil {
			// Try with to-tag as well
			dialog = s.DialogHandler.FindDialogByCallIDAndFromTag(callID, toTag)
		}
	}

	if dialog == nil {
		// No matching dialog found
		return false
	}

	// Update transaction ID for the dialog if provided
	if transactionID != "" {
		dialog.mu.Lock()
		dialog.transactionID = transactionID
		dialog.mu.Unlock()
	}

	// Update remote CSeq if present in the request
	cseqHeader := req.GetHeader("CSeq")
	if cseqHeader != "" {
		parts := strings.Split(cseqHeader, " ")
		if len(parts) > 0 {
			if seq, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
				dialog.mu.Lock()
				dialog.remoteCSeq = seq
				dialog.mu.Unlock()
			}
		}
	}

	// Update dialog's req field with the current request for context
	// if reqMsg, ok := req.Message.(*sip.Request); ok {
	// 	dialog.mu.Lock()
	// 	dialog.req = reqMsg
	// 	dialog.mu.Unlock()
	// }

	// We found a dialog, now handle the request according to its method
	method := req.Method()

	switch method {
	case sip.BYE:
		// Handle BYE request (end dialog)
		res.Ok()
		dialog.SetState(DialogStateTerminated)
		dialog.notifyObservers(DialogEventDestroy)

	case sip.INVITE:
		// Handle re-INVITE (modify dialog)
		dialog.mu.Lock()
		dialog.Remote.SDP = string(req.Body())
		dialog.pendingReinvite = true
		dialog.mu.Unlock()

		// Notify observers first, so they can potentially modify the response
		dialog.notifyObservers(DialogEventReinvite)
		dialog.notifyObservers(DialogEventModify)

		// Automatically respond with the local SDP
		res.WithHeader("Contact", dialog.Local.Contact)

		if dialog.Local.SDP != "" {
			res.WithHeader("Content-Type", "application/sdp")
			res.WithContent(dialog.Local.SDP)
		}

		res.Ok()

		// Clear the pending re-INVITE flag now that we've responded
		dialog.mu.Lock()
		dialog.pendingReinvite = false
		dialog.mu.Unlock()

	case sip.ACK:
		// Handle ACK (confirms dialog)
		if dialog.State == DialogStateEarly {
			dialog.SetState(DialogStateConfirmed)
		}
		return true // No response needed for ACK

	case sip.CANCEL:
		// Handle CANCEL (terminates early dialog)
		if dialog.State == DialogStateEarly || dialog.State == DialogStateProceeding {
			dialog.SetState(DialogStateCancelled)
			res.Ok()
			dialog.notifyObservers(DialogEventDestroy)
		} else {
			// CANCEL only valid for early dialogs
			res.BadRequest("CANCEL received for non-early dialog")
		}

	case sip.INFO:
		res.Ok()
		dialog.notifyObservers(DialogEventInfo)

	case sip.MESSAGE:
		res.Ok()
		dialog.notifyObservers(DialogEventMessage)

	case sip.NOTIFY:
		res.Ok()
		dialog.notifyObservers(DialogEventNotify)

	case sip.REFER:
		res.Ok()
		dialog.notifyObservers(DialogEventRefer)

	case sip.UPDATE:
		res.Ok()
		dialog.notifyObservers(DialogEventUpdate)

	default:
		// Unknown method in dialog context, send 501 Not Implemented
		res.NotImplemented()
		return true
	}

	return true
}

func (s *Srf) handleCDREvent(msg *IncomingCDREvent) {
	fmt.Printf("CDR Event: %s from %s at %s\n",
		msg.EventType, msg.Source, msg.Time)
	if msg.CallID != "" {
		fmt.Printf("  Call ID: %s\n", msg.CallID)
	}
}

func (s *Srf) Disconnect() {
	s.wp.Disconnect()
}

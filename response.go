package drachtio

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"
)

// SrfResponse represents a SIP response
type SrfResponse struct {
	*sip.Response
	Raw      *InboundSIPRequest
	wp       *WireProtocol
	req      *sip.Request
	mu       sync.Mutex
	finished bool
}

type SrfResponseSendOptions struct {
	Body       []byte
	StatusCode int
	Reason     string
	Headers    *SrfHeader
}

func NewSrfResponseSendOptions() *SrfResponseSendOptions {
	return &SrfResponseSendOptions{
		Body:       nil,
		Reason:     "OK",
		StatusCode: sip.StatusOK,
		Headers:    NewSrfHeader(),
	}
}

// NewSrfResponse creates a new SrfResponse
func NewSrfResponse(wp *WireProtocol, req *sip.Request, rawMsg *InboundSIPRequest) *SrfResponse {
	return &SrfResponse{
		wp:       wp,
		Raw:      rawMsg,
		req:      req,
		Response: sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil),
	}
}

// Send sends a default OK response
func (r *SrfResponse) Send() {
	r.SendWithReason(r.StatusCode, r.Reason)
}

// SendWithReasonAsync synchronously sends a response with custom status, reason and headers
func (r *SrfResponse) SendAsync(ctx context.Context, opts ...func(*SrfResponseSendOptions)) (*SrfResponse, error) {
	options := NewSrfResponseSendOptions()

	for _, opt := range opts {
		opt(options)
	}

	cmd := r.getSIPCommand(options)
	msg, err := r.wp.RequestAsync(ctx, cmd)
	if err != nil {
		r.wp.logger.Error("Failed to send response",
			"error", err,
			"reqID", msg.MessageID)

		return nil, err
	}

	sipMsg, err := NewSipMessage(msg.RawMsg)
	if err != nil {
		r.wp.logger.Error("Failed to parse SIP message",
			"error", err,
			"reqID", msg.MessageID)

		return nil, err
	}

	sipRes, ok := sipMsg.Message.(*sip.Response)
	if !ok {
		return nil, errors.New("failed to cast to SIP response")
	}

	res := NewSrfResponse(r.wp, r.req, msg.ToInboundSIPRequest())
	res.WithResponse(sipRes)

	r.markFinished()

	return res, err
}

// SendWithReason sends a response with custom status, reason and headers
func (r *SrfResponse) SendWithReason(statusCode int, reason string, customHeaders ...*SrfHeader) {
	opts := NewSrfResponseSendOptions()
	opts.StatusCode = statusCode
	opts.Reason = reason

	if len(customHeaders) > 0 {
		opts.Headers = customHeaders[0]
	}

	cmd := r.getSIPCommand(opts)

	if _, err := r.wp.Request(cmd); err == nil {
		r.markFinished()
	}
}

// SendWithReason sends a response with custom status, reason and headers
func (r *SrfResponse) getSIPCommand(options *SrfResponseSendOptions) *WireSIPCommand {
	cloneRes := r.Response.Clone()
	cloneRes.StatusCode = options.StatusCode
	cloneRes.Reason = options.Reason
	if options.Body != nil {
		cloneRes.SetBody(options.Body)
	}

	r.appendCustomHeaders(cloneRes, options.Headers)
	cmdOpts := r.buildCommandOptions()

	return NewWireSIPCommand(cloneRes.String(), cmdOpts...)
}

// IsFinished returns whether the response has been sent
func (r *SrfResponse) IsFinished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished
}

func (r *SrfResponse) HasBeenSent() bool {
	return r.IsFinished()
}

// markFinished sets the finished flag
func (r *SrfResponse) markFinished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = true
}

// WithResponse replaces the internal response
func (r *SrfResponse) WithResponse(res *sip.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Response = res
}

// WithContent sets the body of the response
func (r *SrfResponse) WithContent(body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.SetBody([]byte(body))
}

// WithContentType sets the Content-Type header
func (r *SrfResponse) WithContentType(contentType string) {
	r.WithHeader("Content-Type", contentType)
}

// WithStatusCode sets the status code
func (r *SrfResponse) WithStatusCode(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.StatusCode = code
}

// WithReason sets the reason phrase
func (r *SrfResponse) WithReason(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Reason = reason
}

// WithHeader sets or replaces a header
func (r *SrfResponse) WithHeader(key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.HasHeader(key) {
		r.ReplaceHeader(sip.NewHeader(key, value))
	} else {
		r.AppendHeader(sip.NewHeader(key, value))
	}
}

// HasHeader checks if a header exists
func (r *SrfResponse) HasHeader(key string) bool {
	return r.GetHeader(key) != nil
}

// appendCustomHeaders adds custom headers if they are not already present
func (r *SrfResponse) appendCustomHeaders(res *sip.Response, headers ...*SrfHeader) {
	for _, hdr := range headers {
		for _, header := range hdr.ToSIP() {
			if r.HasHeader(header.Name()) {
				res.ReplaceHeader(header)
			} else {
				res.AppendHeader(header)
			}
		}
	}
}

// buildCommandOptions constructs options based on transaction or dialog IDs
func (r *SrfResponse) buildCommandOptions() []SIPCommandOption {
	var opts []SIPCommandOption

	if r.Raw.DialogID != "" {
		opts = append(opts, func(cmd *WireSIPCommand) {
			cmd.dialogID = r.Raw.DialogID
		})
	}

	if r.Raw.TransactionID != "" {
		opts = append(opts, func(cmd *WireSIPCommand) {
			cmd.transactionID = r.Raw.TransactionID
		})
	}

	return opts
}

// withReason joins reasons into a single string or returns a fallback
func withReason(reasons []string, fallback string) string {
	if len(reasons) > 0 {
		return strings.Join(reasons, ",")
	}

	return fallback
}

// 1xx Provisional
func (r *SrfResponse) Trying(reasons ...string) {
	r.SendWithReason(sip.StatusTrying, withReason(reasons, "Trying"))
}

func (r *SrfResponse) Ringing(reasons ...string) {
	r.SendWithReason(sip.StatusRinging, withReason(reasons, "Ringing"))
}

func (r *SrfResponse) CallIsForwarded(reasons ...string) {
	r.SendWithReason(sip.StatusCallIsForwarded, withReason(reasons, "Call Is Being Forwarded"))
}

func (r *SrfResponse) Queued(reasons ...string) {
	r.SendWithReason(sip.StatusQueued, withReason(reasons, "Queued"))
}

func (r *SrfResponse) SessionInProgress(reasons ...string) {
	r.SendWithReason(sip.StatusSessionInProgress, withReason(reasons, "Session In Progress"))
}

// 2xx Successful
func (r *SrfResponse) Ok(reasons ...string) {
	r.SendWithReason(sip.StatusOK, withReason(reasons, "OK"))
}

func (r *SrfResponse) Accepted(reasons ...string) {
	r.SendWithReason(sip.StatusAccepted, withReason(reasons, "Accepted"))
}

// 3xx Redirection
func (r *SrfResponse) MovedPermanently(reasons ...string) {
	r.SendWithReason(sip.StatusMovedPermanently, withReason(reasons, "Moved Permanently"))
}

func (r *SrfResponse) MovedTemporarily(reasons ...string) {
	r.SendWithReason(sip.StatusMovedTemporarily, withReason(reasons, "Moved Temporarily"))
}

func (r *SrfResponse) UseProxy(reasons ...string) {
	r.SendWithReason(sip.StatusUseProxy, withReason(reasons, "Use Proxy"))
}

// 4xx Client Failure
func (r *SrfResponse) BadRequest(reasons ...string) {
	r.SendWithReason(sip.StatusBadRequest, withReason(reasons, "Bad Request"))
}

func (r *SrfResponse) Unauthorized(reasons ...string) {
	r.SendWithReason(sip.StatusUnauthorized, withReason(reasons, "Unauthorized"))
}

func (r *SrfResponse) PaymentRequired(reasons ...string) {
	r.SendWithReason(sip.StatusPaymentRequired, withReason(reasons, "Payment Required"))
}

func (r *SrfResponse) Forbidden(reasons ...string) {
	r.SendWithReason(sip.StatusForbidden, withReason(reasons, "Forbidden"))
}

func (r *SrfResponse) NotFound(reasons ...string) {
	r.SendWithReason(sip.StatusNotFound, withReason(reasons, "Not Found"))
}

func (r *SrfResponse) MethodNotAllowed(reasons ...string) {
	r.SendWithReason(sip.StatusMethodNotAllowed, withReason(reasons, "Method Not Allowed"))
}

func (r *SrfResponse) NotAcceptable(reasons ...string) {
	r.SendWithReason(sip.StatusNotAcceptable, withReason(reasons, "Not Acceptable"))
}

func (r *SrfResponse) ProxyAuthRequired(reasons ...string) {
	r.SendWithReason(sip.StatusProxyAuthRequired, withReason(reasons, "Proxy Authentication Required"))
}

func (r *SrfResponse) RequestTimeout(reasons ...string) {
	r.SendWithReason(sip.StatusRequestTimeout, withReason(reasons, "Request Timeout"))
}

func (r *SrfResponse) Conflict(reasons ...string) {
	r.SendWithReason(sip.StatusConflict, withReason(reasons, "Conflict"))
}

func (r *SrfResponse) Gone(reasons ...string) {
	r.SendWithReason(sip.StatusGone, withReason(reasons, "Gone"))
}

func (r *SrfResponse) RequestEntityTooLarge(reasons ...string) {
	r.SendWithReason(sip.StatusRequestEntityTooLarge, withReason(reasons, "Request Entity Too Large"))
}

func (r *SrfResponse) RequestURITooLong(reasons ...string) {
	r.SendWithReason(sip.StatusRequestURITooLong, withReason(reasons, "Request-URI Too Long"))
}

func (r *SrfResponse) UnsupportedMediaType(reasons ...string) {
	r.SendWithReason(sip.StatusUnsupportedMediaType, withReason(reasons, "Unsupported Media Type"))
}

func (r *SrfResponse) RequestedRangeNotSatisfiable(reasons ...string) {
	r.SendWithReason(sip.StatusRequestedRangeNotSatisfiable, withReason(reasons, "Requested Range Not Satisfiable"))
}

func (r *SrfResponse) BadExtension(reasons ...string) {
	r.SendWithReason(sip.StatusBadExtension, withReason(reasons, "Bad Extension"))
}

func (r *SrfResponse) ExtensionRequired(reasons ...string) {
	r.SendWithReason(sip.StatusExtensionRequired, withReason(reasons, "Extension Required"))
}

func (r *SrfResponse) IntervalTooBrief(reasons ...string) {
	r.SendWithReason(sip.StatusIntervalToBrief, withReason(reasons, "Interval Too Brief"))
}

func (r *SrfResponse) TemporarilyUnavailable(reasons ...string) {
	r.SendWithReason(sip.StatusTemporarilyUnavailable, withReason(reasons, "Temporarily Unavailable"))
}

func (r *SrfResponse) CallTransactionDoesNotExist(reasons ...string) {
	r.SendWithReason(sip.StatusCallTransactionDoesNotExists, withReason(reasons, "Call/Transaction Does Not Exist"))
}

func (r *SrfResponse) LoopDetected(reasons ...string) {
	r.SendWithReason(sip.StatusLoopDetected, withReason(reasons, "Loop Detected"))
}

func (r *SrfResponse) TooManyHops(reasons ...string) {
	r.SendWithReason(sip.StatusTooManyHops, withReason(reasons, "Too Many Hops"))
}

func (r *SrfResponse) AddressIncomplete(reasons ...string) {
	r.SendWithReason(sip.StatusAddressIncomplete, withReason(reasons, "Address Incomplete"))
}

func (r *SrfResponse) Ambiguous(reasons ...string) {
	r.SendWithReason(sip.StatusAmbiguous, withReason(reasons, "Ambiguous"))
}

func (r *SrfResponse) BusyHere(reasons ...string) {
	r.SendWithReason(sip.StatusBusyHere, withReason(reasons, "Busy Here"))
}

func (r *SrfResponse) RequestTerminated(reasons ...string) {
	r.SendWithReason(sip.StatusRequestTerminated, withReason(reasons, "Request Terminated"))
}

func (r *SrfResponse) NotAcceptableHere(reasons ...string) {
	r.SendWithReason(sip.StatusNotAcceptableHere, withReason(reasons, "Not Acceptable Here"))
}

// 5xx Server Failure
func (r *SrfResponse) InternalServerError(reasons ...string) {
	r.SendWithReason(sip.StatusInternalServerError, withReason(reasons, "Internal Server Error"))
}

func (r *SrfResponse) NotImplemented(reasons ...string) {
	r.SendWithReason(sip.StatusNotImplemented, withReason(reasons, "Not Implemented"))
}

func (r *SrfResponse) BadGateway(reasons ...string) {
	r.SendWithReason(sip.StatusBadGateway, withReason(reasons, "Bad Gateway"))
}

func (r *SrfResponse) ServiceUnavailable(reasons ...string) {
	r.SendWithReason(sip.StatusServiceUnavailable, withReason(reasons, "Service Unavailable"))
}

func (r *SrfResponse) GatewayTimeout(reasons ...string) {
	r.SendWithReason(sip.StatusGatewayTimeout, withReason(reasons, "Gateway Timeout"))
}

func (r *SrfResponse) VersionNotSupported(reasons ...string) {
	r.SendWithReason(sip.StatusVersionNotSupported, withReason(reasons, "SIP Version Not Supported"))
}

func (r *SrfResponse) MessageTooLarge(reasons ...string) {
	r.SendWithReason(sip.StatusMessageTooLarge, withReason(reasons, "Message Too Large"))
}

// 6xx Global Failure
func (r *SrfResponse) BusyEverywhere(reasons ...string) {
	r.SendWithReason(sip.StatusGlobalBusyEverywhere, withReason(reasons, "Busy Everywhere"))
}

func (r *SrfResponse) GlobalDecline(reasons ...string) {
	r.SendWithReason(sip.StatusGlobalDecline, withReason(reasons, "Decline"))
}

func (r *SrfResponse) DoesNotExistAnywhere(reasons ...string) {
	r.SendWithReason(sip.StatusGlobalDoesNotExistAnywhere, withReason(reasons, "Does Not Exist Anywhere"))
}

func (r *SrfResponse) GlobalNotAcceptable(reasons ...string) {
	r.SendWithReason(sip.StatusGlobalNotAcceptable, withReason(reasons, "Not Acceptable"))
}

func (r *SrfResponse) SendAck() {
	if r.StatusCode >= 200 && r.req.Method == sip.INVITE {
		r.Ack()
	} else if r.StatusCode > 100 && r.StatusCode < 200 {
		if prackNeeded := r.HasHeader("RSeq"); prackNeeded {
			r.Prack()
		}
	}
}

func (r *SrfResponse) Ack() {
	if r.req.Method != sip.INVITE {
		return
	}

	ackReq := sip.NewRequest(sip.ACK, r.req.Recipient)
	r.sendAck(sip.ACK, ackReq)
}

func (r *SrfResponse) Prack() {
	if r.req.Method != sip.INVITE {
		return
	}

	rseq := r.GetHeader("RSeq")
	if rseq == nil {
		return
	}

	cseq := r.req.GetHeader("CSeq")
	if cseq == nil {
		return
	}

	rack := rseq.Value() + " " + cseq.Value()

	prackReq := sip.NewRequest(sip.PRACK, r.req.Recipient)
	prackReq.AppendHeader(sip.NewHeader("RAck", rack))
	r.sendAck(sip.PRACK, prackReq)
}

func (r *SrfResponse) sendAck(method sip.RequestMethod, ackReq *sip.Request) {
	opts := []SIPCommandOption{}

	if r.Raw.DialogID != "" {
		opts = append(opts, func(cmd *WireSIPCommand) {
			cmd.dialogID = r.Raw.DialogID
		})
	}

	if r.Raw.TransactionID != "" {
		opts = append(opts, func(cmd *WireSIPCommand) {
			cmd.transactionID = r.Raw.TransactionID
		})
	}

	cmd := NewWireSIPCommand(ackReq.String(), opts...)
	if reqID, err := r.wp.Request(cmd); err != nil {
		r.wp.logger.Error("Failed to send ACK",
			"error", err,
			"reqID", reqID)
	}
}

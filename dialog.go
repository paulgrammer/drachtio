package drachtio

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

type DialogState string

const (
	DialogStateTrying     DialogState = "trying"
	DialogStateProceeding DialogState = "proceeding"
	DialogStateEarly      DialogState = "early"
	DialogStateConfirmed  DialogState = "confirmed"
	DialogStateTerminated DialogState = "terminated"
	DialogStateRejected   DialogState = "rejected"
	DialogStateCancelled  DialogState = "cancelled"
)

type DialogDirection string

const (
	DialogDirectionInitiator DialogDirection = "initiator"
	DialogDirectionRecipient DialogDirection = "recipient"
)

type DialogType string

const (
	DialogTypeUAS DialogType = "uas"
	DialogTypeUAC DialogType = "uac"
)

type SipDialogInfo struct {
	CallID    string
	LocalTag  string
	RemoteTag string
}

// DialogSide represents one side of a SIP dialog (local or remote)
// Modeled after the JS implementation with equivalent fields
type DialogSide struct {
	URI     string // SIP URI (e.g., "sip:user@domain.com")
	SDP     string // Session Description Protocol body
	Contact string // Contact header value
	OnHold  bool   // Whether this side has put the call on hold
}

type DestroyOptions struct {
	Headers map[string]string
	Auth    *AuthCredentials
}

type ModifyOptions struct {
	Headers map[string]string
	Auth    *AuthCredentials
	NoAck   bool
}

type CreateUACOptions struct {
	URI           *sip.Uri
	Method        sip.RequestMethod
	Headers       *SrfHeader
	LocalSDP      string
	Auth          *AuthCredentials
	Proxy         string
	From          *sip.Uri
	cbRequest     func(*SrfRequest)
	cbProvisional func(*SrfResponse, *SrfRequest)
}

type CreateUASOptions struct {
	Headers  *SrfHeader
	LocalSDP string
}

type CreateB2BUAOptions struct {
	URI                  string
	Headers              *SrfHeader
	ResponseHeaders      *SrfHeader
	LocalSdpA            string
	LocalSdpB            string
	ProxyRequestHeaders  []string
	ProxyResponseHeaders []string
	PassFailure          bool
	PassProvisional      bool
	Proxy                string
	Auth                 *AuthCredentials
}

type DialogStateInfo struct {
	State     DialogState
	Direction DialogDirection
	AOR       string
	CallID    string
	LocalTag  string
	RemoteTag string
	ID        string
}

type DialogEvent int

const (
	DialogEventDestroy DialogEvent = iota
	DialogEventModify
	DialogEventReinvite
	DialogEventInfo
	DialogEventNotify
	DialogEventRefer
	DialogEventMessage
	DialogEventUpdate
)

type DialogObserverFunc func(dialog *Dialog)

// Dialog represents a SIP dialog between two user agents
// Modeled after the JS implementation with equivalent fields and behavior
type Dialog struct {
	ID              string
	Type            DialogType
	SipInfo         SipDialogInfo
	Local           DialogSide
	Remote          DialogSide
	Direction       DialogDirection
	State           DialogState
	StateInfo       DialogStateInfo
	mu              sync.RWMutex
	req             *SrfRequest
	res             *SrfResponse
	wp              *WireProtocol
	observers       map[DialogEvent][]DialogObserverFunc
	localCSeq       uint64  // Track local CSeq for outgoing requests
	remoteCSeq      uint64  // Track remote CSeq for incoming requests
	pendingReinvite bool    // Track if we have a pending re-INVITE
	otherDialog     *Dialog // Reference to the other leg in a B2BUA scenario
	transactionID   string  // Current transaction ID
	callID          string  // Convenience field to store Call-ID for quicker lookups

	// Used to manage concurrent reinvites (similar to JS implementation)
	reinvitesInProgress struct {
		count    int
		admitOne []chan struct{} // Signal channels for managing concurrent reinvites
	}

	// List of subscriptions created by this dialog
	subscriptions []*SrfRequest
}

// NewDialog creates a new Dialog instance.
// This constructor follows the design pattern of the JavaScript drachtio-srf library.
//
// Parameters:
// - id: Unique dialog identifier
// - wp: WireProtocol instance for sending messages
// - req: SIP request associated with this dialog
// - res: SIP response associated with this dialog
// - dialogType: Type of dialog ("uas" or "uac")
// - sipInfo: SIP dialog information (Call-ID, tags)
// - local: Local dialog side information
// - remote: Remote dialog side information
func NewDialog(id string, wp *WireProtocol, req *SrfRequest, res *SrfResponse, dialogType DialogType, sipInfo SipDialogInfo, local, remote DialogSide) *Dialog {
	// Validate the dialog type
	switch dialogType {
	case DialogTypeUAS, DialogTypeUAC:
		// Valid types
	default:
		// Use a default type if invalid
		wp.logger.Warn("Invalid dialog type specified, defaulting to UAC", "type", string(dialogType))
		dialogType = DialogTypeUAC
	}

	// Parse initial CSeq from request if available
	var initialCSeq uint64 = 1
	if req != nil {
		if cseqHeader := req.GetHeader("CSeq"); cseqHeader != "" {
			parts := strings.Split(cseqHeader, " ")
			if len(parts) > 0 {
				if seq, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
					initialCSeq = seq
				}
			}
		}
	}

	// Determine initial dialog state based on dialog type
	initialState := DialogStateTrying
	if dialogType == DialogTypeUAS {
		initialState = DialogStateProceeding
	}

	// Determine initial dialog direction
	initialDirection := DialogDirectionInitiator
	if dialogType == DialogTypeUAS {
		initialDirection = DialogDirectionRecipient
	}

	// Ensure dialog sides have all required fields
	if local.Contact == "" && dialogType == DialogTypeUAC {
		// For UAC, use a default contact if none provided
		local.Contact = "<sip:anonymous@anonymous.invalid>"
	}

	// Check if we need to extract SIP info (callId, tags) from req/res
	// This happens if sipInfo wasn't provided fully by the caller
	if sipInfo.CallID == "" && res != nil {
		// Extract Call-ID - in JS this is "this.sip = { callId: this.res.get('Call-ID') ... }"
		sipInfo.CallID = res.GetHeader("Call-ID").Value()
	}

	// Initialize a new Dialog object
	dialog := &Dialog{
		wp:              wp,
		ID:              id,
		req:             req,
		res:             res,
		Type:            dialogType,
		SipInfo:         sipInfo,
		Local:           local,
		Remote:          remote,
		State:           initialState,
		Direction:       initialDirection,
		observers:       make(map[DialogEvent][]DialogObserverFunc),
		localCSeq:       initialCSeq,
		remoteCSeq:      initialCSeq,
		pendingReinvite: false,
		otherDialog:     nil,
		transactionID:   "",
		callID:          sipInfo.CallID,
		subscriptions:   []*SrfRequest{},
	}

	// Initialize dialog state info
	dialog.updateDialogStateInfo()

	// Check if this dialog was created for a SUBSCRIBE request
	if req != nil && req.Method() == sip.SUBSCRIBE {
		dialog.addSubscription(req)
	}

	return dialog
}

// SetTransactionID sets the transaction ID for the dialog.
func (d *Dialog) SetTransactionID(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.transactionID = id
}

// Destroy terminates the dialog by sending a BYE (for confirmed dialogs) or CANCEL (for early dialogs).
// It accepts optional options to customize the termination request.
func (d *Dialog) Destroy(opts ...func(*DestroyOptions)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	options := DestroyOptions{
		Headers: make(map[string]string),
	}

	for _, opt := range opts {
		opt(&options)
	}

	if d.State == DialogStateTerminated {
		return nil
	}

	var err error

	switch d.State {
	case DialogStateConfirmed:
		err = d.sendRequest(&RequestOptions{
			Method:  sip.BYE,
			Headers: options.Headers,
			Auth:    options.Auth,
		})
	case DialogStateEarly, DialogStateProceeding:
		err = d.sendRequest(&RequestOptions{
			Method:  sip.CANCEL,
			Headers: options.Headers,
			Auth:    options.Auth,
		})
	}
	d.State = DialogStateTerminated
	d.notifyObservers(DialogEventDestroy)

	return err
}

// Modify updates the dialog by sending a re-INVITE with a new SDP.
// This is typically used to change media attributes, put calls on hold, etc.
func (d *Dialog) Modify(sdp string, opts ...func(*ModifyOptions)) error {
	d.mu.Lock()

	options := ModifyOptions{
		Headers: make(map[string]string),
	}

	for _, opt := range opts {
		opt(&options)
	}

	if d.State != DialogStateConfirmed {
		d.mu.Unlock()
		return fmt.Errorf("cannot modify dialog in state %s", d.State)
	}

	if d.pendingReinvite {
		d.mu.Unlock()
		return fmt.Errorf("cannot send re-INVITE while another one is in progress")
	}

	d.mu.Unlock() // Unlock before sending the request

	// Check if this is a hold operation
	isHold := false
	if strings.Contains(sdp, "a=inactive") || strings.Contains(sdp, "a=sendonly") {
		isHold = true
	}

	reqOpts := &RequestOptions{
		Method:  sip.INVITE,
		Headers: options.Headers,
		Auth:    options.Auth,
		Body:    sdp,
		NoAck:   options.NoAck,
	}

	err := d.request(reqOpts)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.Local.SDP = sdp

	// Update the on-hold status
	if isHold {
		d.Local.OnHold = true
	} else if strings.Contains(sdp, "a=sendrecv") {
		d.Local.OnHold = false
	}
	d.mu.Unlock()

	// Notify observers about the modification
	d.notifyObservers(DialogEventModify)

	return nil
}

func (d *Dialog) request(opts *RequestOptions) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.State == DialogStateTerminated {
		return fmt.Errorf("cannot send request on terminated dialog")
	}
	return d.sendRequest(opts)
}

func (d *Dialog) sendRequest(opts *RequestOptions) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// For re-INVITE, check if we already have one pending
	if opts.Method == sip.INVITE && d.pendingReinvite {
		return fmt.Errorf("cannot send re-INVITE while another one is in progress")
	}

	// Create remote URI for recipient
	recipient := &sip.Uri{}
	if err := sip.ParseUri(d.Remote.URI, recipient); err != nil {
		return fmt.Errorf("failed to parse remote URI: %v", err)
	}

	// Create a new SIP request
	localReq := sip.NewRequest(opts.Method, *recipient)

	// Set Call-ID
	localReq.AppendHeader(sip.NewHeader("Call-ID", d.SipInfo.CallID))

	// Build From and To headers with tags
	localReq.AppendHeader(sip.NewHeader("From", fmt.Sprintf("%s;tag=%s", d.Local.URI, d.SipInfo.LocalTag)))
	localReq.AppendHeader(sip.NewHeader("To", fmt.Sprintf("%s;tag=%s", d.Remote.URI, d.SipInfo.RemoteTag)))

	// Increment and set CSeq for new request
	cseq := d.localCSeq
	if opts.Method != sip.ACK {
		// ACK uses the same CSeq as the INVITE, don't increment
		d.localCSeq++
		cseq = d.localCSeq
	}
	localReq.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d %s", cseq, opts.Method)))

	// Set Contact header
	localReq.AppendHeader(sip.NewHeader("Contact", d.Local.Contact))

	// Set Max-Forwards header if not present
	if localReq.GetHeader("Max-Forwards") == nil {
		localReq.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	}

	// Set body if provided
	if opts.Body != "" {
		localReq.SetBody([]byte(opts.Body))

		// Set Content-Type if not already set
		if _, hasContentType := opts.Headers["Content-Type"]; !hasContentType {
			localReq.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		}
	}

	// Add custom headers
	for key, value := range opts.Headers {
		localReq.AppendHeader(sip.NewHeader(key, value))
	}

	// Create the wire command for sending
	cmd := NewWireSIPCommand(localReq.String(), func(cmd *WireSIPCommand) {
		cmd.dialogID = d.ID

		// Set proxy if specified
		if opts.Proxy != "" {
			cmd.proxy = opts.Proxy
		}

		// Handle auth in the command option function
		if opts.Auth != nil {
			// We would need to add auth functionality to the WireSIPCommand
			// For now, we just log that auth was requested
			fmt.Printf("Auth requested for dialog %s but not implemented yet\n", d.ID)
		}
	})

	// Mark dialog as having a pending re-INVITE if this is one
	if opts.Method == sip.INVITE {
		d.pendingReinvite = true
	}

	// Send the request - for dialog operations, we typically don't need to wait for a response
	// as dialog responses are handled asynchronously via the handleSIPResponse function
	// Note: The ID returned by wp.Request() is NOT the SIP transaction ID - that comes from
	// the server's response in the InboundSIPRequest passed to handleSIPResponse
	_, err := d.wp.Request(cmd)
	if err != nil {
		if opts.Method == sip.INVITE {
			d.pendingReinvite = false // Reset the flag if request failed
		}
		return err
	}

	// We don't store the request ID from wp.Request() as the transaction ID
	// The real transaction ID comes from drachtio server's response and is handled in handleSIPResponse

	// For UAC BYE requests, we auto-terminate the dialog to avoid race conditions
	if d.Type == DialogTypeUAC && opts.Method == sip.BYE {
		d.State = DialogStateTerminated
		d.updateDialogStateInfo()
	}

	return nil
}

func (d *Dialog) Info(body string, headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	}

	return d.request(&RequestOptions{
		Method:  sip.INFO,
		Body:    body,
		Headers: headers,
	})
}

func (d *Dialog) Notify(body string, headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	}

	return d.request(&RequestOptions{
		Method:  sip.NOTIFY,
		Body:    body,
		Headers: headers,
	})
}

func (d *Dialog) Refer(referTo string, headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	}

	headers["Refer-To"] = referTo

	return d.request(&RequestOptions{
		Method:  sip.REFER,
		Headers: headers,
	})
}

func (d *Dialog) Update(body string, headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	}

	return d.request(&RequestOptions{
		Method:  sip.UPDATE,
		Body:    body,
		Headers: headers,
	})
}

func (d *Dialog) Message(body string, headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	} else {
		headers = make(map[string]string)
	}

	// Set content type for message if not provided
	if _, hasContentType := headers["Content-Type"]; !hasContentType && body != "" {
		headers["Content-Type"] = "text/plain"
	}

	return d.request(&RequestOptions{
		Method:  sip.MESSAGE,
		Body:    body,
		Headers: headers,
	})
}

// Ack sends an ACK request in response to a 2xx response to an INVITE
func (d *Dialog) Ack(headerOpts ...map[string]string) error {
	var headers map[string]string

	if len(headerOpts) > 0 {
		headers = headerOpts[0]
	} else {
		headers = make(map[string]string)
	}

	// ACK is a special case - it's not sent through the request method
	// because it doesn't expect a response and needs special handling
	ackOpts := &RequestOptions{
		Method:  sip.ACK,
		Headers: headers,
	}

	// Send ACK directly rather than through request()
	return d.sendRequest(ackOpts)
}

func (d *Dialog) addObserver(event DialogEvent, observer DialogObserverFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observers[event] = append(d.observers[event], observer)
}

func (d *Dialog) notifyObservers(event DialogEvent) {
	observers := d.observers[event]
	for _, observer := range observers {
		observer(d)
	}
}

func (d *Dialog) OnDestroy(fn func(*Dialog)) {
	d.addObserver(DialogEventDestroy, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnModify(fn func(*Dialog)) {
	d.addObserver(DialogEventModify, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnReinvite(fn func(*Dialog)) {
	d.addObserver(DialogEventReinvite, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnInfo(fn func(*Dialog)) {
	d.addObserver(DialogEventInfo, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnNotify(fn func(*Dialog)) {
	d.addObserver(DialogEventNotify, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnRefer(fn func(*Dialog)) {
	d.addObserver(DialogEventRefer, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnMessage(fn func(*Dialog)) {
	d.addObserver(DialogEventMessage, func(dialog *Dialog) { fn(dialog) })
}

func (d *Dialog) OnUpdate(fn func(*Dialog)) {
	d.addObserver(DialogEventUpdate, func(dialog *Dialog) { fn(dialog) })
}

// addSubscription adds a subscription to the dialog.
// This is used for SUBSCRIBE requests.
func (d *Dialog) addSubscription(req *SrfRequest) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Add to the subscriptions list
	d.subscriptions = append(d.subscriptions, req)
}

func (d *Dialog) SetState(state DialogState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.State = state
	d.updateDialogStateInfo()
}

// Hold places the dialog on hold by sending a re-INVITE with appropriate SDP
func (d *Dialog) Hold(opts ...func(*ModifyOptions)) error {
	d.mu.RLock()
	currentSDP := d.Local.SDP
	d.mu.RUnlock()

	// If we don't have local SDP yet, we can't put call on hold
	if currentSDP == "" {
		return fmt.Errorf("cannot put call on hold without local SDP")
	}

	// Create hold SDP by modifying the current SDP
	// Replace a=sendrecv with a=sendonly or add a=sendonly if not present
	holdSDP := currentSDP
	if strings.Contains(holdSDP, "a=sendrecv") {
		holdSDP = strings.Replace(holdSDP, "a=sendrecv", "a=sendonly", -1)
	} else if !strings.Contains(holdSDP, "a=sendonly") && !strings.Contains(holdSDP, "a=inactive") {
		// If neither sendrecv or sendonly/inactive is present, add sendonly to each media section
		mediaLines := strings.Split(holdSDP, "m=")
		for i := 1; i < len(mediaLines); i++ {
			mediaLines[i] = mediaLines[i] + "a=sendonly\r\n"
		}
		holdSDP = strings.Join(mediaLines, "m=")
	}

	// Send the modified SDP
	return d.Modify(holdSDP, opts...)
}

// Unhold resumes the dialog by sending a re-INVITE with appropriate SDP
func (d *Dialog) Unhold(opts ...func(*ModifyOptions)) error {
	d.mu.RLock()
	currentSDP := d.Local.SDP
	d.mu.RUnlock()

	// If we don't have local SDP yet, we can't resume the call
	if currentSDP == "" {
		return fmt.Errorf("cannot resume call without local SDP")
	}

	// Create active SDP by modifying the current SDP
	// Replace a=sendonly or a=inactive with a=sendrecv
	activeSDP := currentSDP
	if strings.Contains(activeSDP, "a=sendonly") {
		activeSDP = strings.Replace(activeSDP, "a=sendonly", "a=sendrecv", -1)
	} else if strings.Contains(activeSDP, "a=inactive") {
		activeSDP = strings.Replace(activeSDP, "a=inactive", "a=sendrecv", -1)
	} else if !strings.Contains(activeSDP, "a=sendrecv") {
		// If neither sendrecv or sendonly/inactive is present, add sendrecv to each media section
		mediaLines := strings.Split(activeSDP, "m=")
		for i := 1; i < len(mediaLines); i++ {
			mediaLines[i] = mediaLines[i] + "a=sendrecv\r\n"
		}
		activeSDP = strings.Join(mediaLines, "m=")
	}

	// Send the modified SDP
	return d.Modify(activeSDP, opts...)
}

func (d *Dialog) updateDialogStateInfo() {
	d.StateInfo = DialogStateInfo{
		State:     d.State,
		Direction: d.Direction,
		CallID:    d.SipInfo.CallID,
		LocalTag:  d.SipInfo.LocalTag,
		RemoteTag: d.SipInfo.RemoteTag,
		ID:        d.ID,
	}
}

type DialogHandler struct {
	dialogs sync.Map
	wp      *WireProtocol
}

func NewDialogHandler(wp *WireProtocol) *DialogHandler {
	return &DialogHandler{wp: wp}
}

func (dh *DialogHandler) FindDialogById(id string) *Dialog {
	if val, ok := dh.dialogs.Load(id); ok {
		if dialog, ok := val.(*Dialog); ok {
			return dialog
		}
	}
	return nil
}

func (dh *DialogHandler) FindDialogByCallIDAndFromTag(callId, tag string) *Dialog {
	var result *Dialog

	// First try to match by callID and tags
	dh.dialogs.Range(func(key, value interface{}) bool {
		if dialog, ok := value.(*Dialog); ok {
			// Check if this dialog matches the criteria
			if dialog.SipInfo.CallID == callId && (dialog.SipInfo.LocalTag == tag || dialog.SipInfo.RemoteTag == tag) {
				result = dialog
				return false // Stop iterating
			}
		}
		return true // Continue iterating
	})

	// If no match found, try by callID only
	if result == nil {
		dh.dialogs.Range(func(key, value interface{}) bool {
			if dialog, ok := value.(*Dialog); ok {
				if dialog.SipInfo.CallID == callId {
					// Found a matching dialog by Call-ID
					result = dialog
					return false // Stop iterating
				}
			}
			return true // Continue iterating
		})
	}

	return result
}

func (dh *DialogHandler) CreateUAS(req *SrfRequest, res *SrfResponse, opts ...func(*CreateUASOptions)) (*Dialog, error) {
	options := CreateUASOptions{
		Headers: NewSrfHeader(),
	}

	for _, opt := range opts {
		opt(&options)
	}

	// Get dialog information from request
	if req.From() == nil {
		return nil, fmt.Errorf("failed to create UAS dialog, missing FROM header")
	}

	if req.To() == nil {
		return nil, fmt.Errorf("failed to create UAS dialog, missing TO header")
	}

	if !req.HasHeader("Contact") {
		return nil, fmt.Errorf("failed to create UAS dialog, missing CONTACT header")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if options.LocalSDP != "" {
		options.Headers.Add("Content-Type", "application/sdp")
	}

	req.OnCancel(func(sr *SrfRequest) {
		// Handle cancellation of the request
		// callback(new SipError(487, 'Request Terminated')) ;
	})

	// Send the response
	sentRes, err := res.SendAsync(ctx, func(o *SrfResponseSendOptions) {
		o.Headers = options.Headers
		o.Body = []byte(options.LocalSDP)

		if req.Method() == sip.INVITE {
			o.StatusCode = sip.StatusOK
			o.Reason = "OK"
		} else {
			o.StatusCode = sip.StatusAccepted
			o.Reason = "Accepted"
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to send response: %v", err)
	}

	// Create dialog
	sipInfo := SipDialogInfo{
		CallID: req.CallID().Value(),
	}

	// Generate a new tag for the remote side
	// For UAS, remote tag is from the From header of the request
	if fromTag, ok := req.From().Params.Get("tag"); ok {
		sipInfo.RemoteTag = fromTag
	}

	// Generate a new tag for the local side
	// For UAS, local tag is from the To header of the response
	if sentRes.To() != nil {
		if sentToTag, ok := sentRes.To().Params.Get("tag"); ok {
			sipInfo.LocalTag = sentToTag
		}
	}

	// Set up local side
	// For UAS, local side is the one sending the response
	local := DialogSide{
		SDP: string(sentRes.Body()),
	}

	// Set local URI from the request
	if sentRes.Contact() != nil {
		local.URI = sentRes.Contact().Address.String()
		local.Contact = sentRes.Contact().Value()
	}

	// Set up remote side
	// For UAS, remote side is the one sending the request
	remote := DialogSide{
		SDP: string(req.Body()),
	}

	// Set remote URI from the request
	if contacts := req.GetHeaders("Contact"); len(contacts) > 0 {
		if contactHeader, ok := contacts[0].(*sip.ContactHeader); ok {
			remote.URI = contactHeader.Address.String()
		}
	}

	// Create the dialog
	sipReq, ok := req.Message.(*sip.Request)
	if !ok {
		return nil, errors.New("req message is not a valid sip message")
	}

	// Generate a unique dialog ID
	id, err := MakeDialogIDFromRequest(sipReq)
	if err != nil {
		return nil, err
	}

	dialog := NewDialog(id, res.wp, req, res, DialogTypeUAS, sipInfo, local, remote)
	dialog.Direction = DialogDirectionRecipient
	dialog.SetState(DialogStateProceeding)

	dialog.OnDestroy(func(d *Dialog) {
		dh.dialogs.Delete(d.ID)
	})

	return dialog, nil
}

func (dh *DialogHandler) CreateUAC(opts ...func(*CreateUACOptions)) (*Dialog, error) {
	options := CreateUACOptions{
		Headers: NewSrfHeader(),
		Method:  sip.INVITE,
	}

	// Apply Options
	for _, opt := range opts {
		opt(&options)
	}

	is3pcc := options.LocalSDP == "" && options.Method == sip.INVITE

	// TODO: Handle 3PCC case
	fmt.Printf("TODO: CreateUAC: is3pcc=%v, method=%s\n", is3pcc, options.Method)

	if options.URI == nil {
		return nil, fmt.Errorf("URI is required for UAC dialog")
	}

	launchRequest := func(uri sip.Uri, method sip.RequestMethod, options *CreateUACOptions) (*SrfRequest, *SrfResponse, error) {
		// Create a new SIP request
		localReq := sip.NewRequest(method, uri)

		// Add body if provided
		localReq.SetBody([]byte(options.LocalSDP))

		// Add any other headers specified in options
		for _, header := range options.Headers.ToSIP() {
			if localReq.GetHeader(header.Name()) == nil {
				localReq.AppendHeader(header)
			}
		}

		// Send the request
		cmd := NewWireSIPCommand(localReq.String(), func(cmd *WireSIPCommand) {
			// Add proxy if specified
			if options.Proxy != "" {
				cmd.proxy = options.Proxy
			}

			// Handle auth in the command option function
			if options.Auth != nil {
				// We would need to add auth functionality to the WireSIPCommand
				// For now, we just log that auth was requested
				fmt.Printf("Auth requested but not implemented yet")
			}
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		inboundRes, err := dh.wp.RequestAsync(ctx, cmd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to send UAC request: %v", err)
		}

		inboundSIP := inboundRes.ToInboundSIPRequest()
		sipMsg, err := NewSipMessage(inboundSIP.SIPMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse SIP message: %v", err)
		}

		remoteReq, ok := sipMsg.Message.(*sip.Request)
		if !ok {
			return nil, nil, errors.New("sipMsg.Message is not a valid sip request")
		}

		srfReq := NewSrfRequest(dh.wp, sipMsg, inboundSIP)
		srfRes := NewSrfResponse(dh.wp, remoteReq, inboundSIP)

		return srfReq, srfRes, nil
	}

	// Generate the SIP request
	srfReq, srfRes, err := launchRequest(*options.URI, options.Method, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create UAC request: %v", err)
	}

	srfReq.OnResponse(func(res *SrfResponse) {
		// res.IsCancel() // Check if the response is a CANCEL
		// res.IsAck() // Check if the response is an ACK
		// res.IsSuccess() // Check if the response is a success (2xx)

		if res.IsProvisional() {
			if res.HasHeader("RSeq") {
				res.SendAck()
			}

			if options.cbProvisional != nil {
				options.cbProvisional(res, srfReq)
			}
		}
	})

	// Generate a unique From tag if needed
	fromHeader := srfReq.From()
	if fromHeader == nil {
		return nil, fmt.Errorf("failed to create CreateUAC request, missing FROM header")
	}

	// Generate a unique dialog ID
	id, err := MakeDialogIDFromRequest(srfReq.Message.(*sip.Request))
	if err != nil {
		return nil, err
	}

	// Create dialog info
	sipInfo := SipDialogInfo{
		CallID: srfReq.CallID().Value(),
	}

	// Generate a new tag for the local side
	if fromTag, ok := srfReq.From().Params.Get("tag"); ok {
		sipInfo.LocalTag = fromTag
	}

	// Generate a new tag for the remote side
	if srfReq.To() != nil {
		if toTag, ok := srfReq.To().Params.Get("tag"); ok {
			sipInfo.RemoteTag = toTag
		}
	}

	// Set up dialog sides
	local := DialogSide{
		URI:    options.URI.String(),
		SDP:    options.LocalSDP,
		OnHold: false,
	}

	// Set local Contact header
	if contactHeader := srfReq.GetHeaders("Contact"); len(contactHeader) > 0 {
		if contact, ok := contactHeader[0].(*sip.ContactHeader); ok {
			local.URI = contact.Address.String()
			local.Contact = contact.Value()
		}
	}

	remote := DialogSide{
		URI:    options.URI.String(),
		SDP:    string(srfReq.Body()),
		OnHold: false,
	}

	// Set remote Contact header
	if contactHeader := srfReq.GetHeaders("Contact"); len(contactHeader) > 0 {
		if contact, ok := contactHeader[0].(*sip.ContactHeader); ok {
			remote.URI = contact.Address.String()
			remote.Contact = contact.Value()
		}
	}

	// Create the dialog object
	dialog := NewDialog(id, dh.wp, srfReq, srfRes, DialogTypeUAC, sipInfo, local, remote)
	dialog.Direction = DialogDirectionInitiator
	dialog.State = DialogStateTrying

	// Store the dialog in our registry
	dh.dialogs.Store(dialog.ID, dialog)

	// Register cleanup on dialog destruction
	dialog.OnDestroy(func(d *Dialog) {
		dh.dialogs.Delete(d.ID)
	})

	// Set up the request handler for the UAC dialog
	if options.cbRequest != nil {
		options.cbRequest(srfReq)
	}

	return dialog, nil
}

func (dh *DialogHandler) CreateB2BUA(req *SrfRequest, res *SrfResponse, destUri sip.Uri, opts ...func(*CreateB2BUAOptions)) (*Dialog, *Dialog, error) {
	options := CreateB2BUAOptions{
		Headers:              NewSrfHeader(),
		ResponseHeaders:      NewSrfHeader(),
		ProxyRequestHeaders:  make([]string, 0),
		ProxyResponseHeaders: make([]string, 0),
		PassFailure:          true,
		PassProvisional:      true,
	}

	// Apply Options
	for _, opt := range opts {
		opt(&options)
	}

	// Copy headers from original request if specified
	if options.ProxyRequestHeaders != nil {
		for _, headerName := range options.ProxyRequestHeaders {
			// Get header values directly from the raw request
			if localReq, ok := req.Message.(*sip.Request); ok {
				if h := localReq.GetHeader(headerName); h != nil {
					options.Headers.Add(h.Name(), h.Value())
				}
			}
		}
	}

	// Apply any headers requested to be passed through
	if options.ResponseHeaders != nil {
		for _, header := range options.ResponseHeaders.ToSIP() {
			res.WithHeader(header.Name(), header.Value())
		}
	}

	// Set Body
	if options.LocalSdpB == "" {
		options.LocalSdpB = string(req.Body())
	}

	// Copy headers from UAC to UAS
	copyUACHeadersToUAS := func(uacRes *SrfResponse) *SrfHeader {
		headers := NewSrfHeader()

		// Copy specified headers from UAC response to UAS response
		for _, headerName := range options.ProxyResponseHeaders {
			if headerName == "all" {
				continue // Special case handled below
			}

			// Skip excluded headers (prefixed with '-')
			if strings.HasPrefix(headerName, "-") {
				continue
			}

			if header := uacRes.GetHeader(headerName); header != nil {
				headers.Add(headerName, header.Value())
			}
		}

		// Handle the 'all' case for header proxying
		if len(options.ProxyResponseHeaders) > 0 && options.ProxyResponseHeaders[0] == "all" {
			// List of headers we don't want to copy
			nonCopyableHeaders := []string{
				"via", "from", "to", "call-id", "cseq",
				"contact", "content-length", "content-type",
			}

			for _, header := range uacRes.Headers() {
				headerName := strings.ToLower(header.Name())
				if SliceContains(nonCopyableHeaders, headerName) {
					continue
				}

				headers.Add(headerName, header.Value())
			}
		}

		return headers
	}

	// Handle UAC sent events
	handleUACSentFn := func(uacReq *SrfRequest) {
		// Set up cancellation handling
		req.OnCancel(func(r *SrfRequest) {
			// If A side cancels, cancel the B side
			if err := req.Cancel(); err == nil {
				// Also respond to the A side with 487 Request Terminated
				if !res.HasBeenSent() {
					res.RequestTerminated()
				}
			}
		})
	}

	// Handle provisional responses
	handleUACProvisionalResponseFn := func(provisionalRes *SrfResponse, uacReq *SrfRequest) {
		if !options.PassProvisional || provisionalRes.StatusCode <= 100 {
			return // Don't forward if not requested or is just a 100 Trying
		}

		headers := copyUACHeadersToUAS(provisionalRes)

		// Forward provisional response to the UAS leg
		if len(provisionalRes.Body()) > 0 {
			// If we have a specific SDP transform for A leg responses, use it
			if options.LocalSdpA != "" {
				// In JS version, this could be either a string or a function
				// Here we just use the string directly for simplicity
				res.WithContent(options.LocalSdpA)
			} else {
				// Otherwise, pass through the SDP from B leg
				res.SetBody(provisionalRes.Body())
			}

			// Otherwise, pass through the SDP from B leg
			res.SetBody(provisionalRes.Body())
			res.WithContentType(provisionalRes.ContentType().Value())
		}

		res.SendWithReason(provisionalRes.StatusCode, provisionalRes.Reason, headers)
	}

	// Create UAC dialog (outgoing dialog)
	uacOptions := CreateUACOptions{
		URI:           &destUri,
		Method:        sip.INVITE,
		Headers:       options.Headers,
		LocalSDP:      options.LocalSdpB,
		Auth:          options.Auth,
		Proxy:         options.Proxy,
		cbRequest:     handleUACSentFn,
		cbProvisional: handleUACProvisionalResponseFn,
	}

	// Create the UAC dialog
	uac, err := dh.CreateUAC(func(o *CreateUACOptions) {
		*o = uacOptions
	})

	if err != nil {
		// Handle any errors according to the PassFailure option
		if options.PassFailure && !res.HasBeenSent() {
			// Pass the failure back to the A leg
			statusCode := 500 // Default error
			reason := "Server Internal Error"

			// Try to extract status code from error if possible
			if sipErr, ok := err.(SipError); ok {
				statusCode = sipErr.Status
				reason = sipErr.Reason
			}

			res.SendWithReason(statusCode, reason)
		}
		return nil, nil, fmt.Errorf("failed to create UAC dialog: %v", err)
	}

	generateSdpA := func(res *SrfResponse) string {
		if options.LocalSdpA != "" {
			// If we have a specific SDP transform for A leg responses, use it
			return options.LocalSdpA
		}

		sdpB := res.Body()
		if sdpB == nil {
			return ""
		}

		return string(sdpB)
	}

	// Final Response
	finalResponse := uac.res

	// Create UAS dialog (incoming dialog)
	uasOptions := CreateUASOptions{
		LocalSDP: generateSdpA(finalResponse),
		Headers:  copyUACHeadersToUAS(finalResponse),
	}

	// Set up the UAS options
	uas, err := dh.CreateUAS(req, res, func(o *CreateUASOptions) {
		*o = uasOptions
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create UAS dialog: %v", err)
	}

	// Link the two dialogs together to form the B2BUA
	uas.mu.Lock()
	uac.mu.Lock()
	uas.otherDialog = uac
	uac.otherDialog = uas
	uas.mu.Unlock()
	uac.mu.Unlock()

	// Send ringing response if not already sent and if passProvisional is false
	if !options.PassProvisional && !res.HasBeenSent() {
		res.Ringing()
	}

	// Store dialogs in dialog handler
	dh.dialogs.Store(uas.ID, uas)
	dh.dialogs.Store(uac.ID, uac)

	return uas, uac, nil
}
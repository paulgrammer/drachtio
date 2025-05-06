package drachtio

import "github.com/emiago/sipgo/sip"

// handleResponse processes a response for a specific dialog
func (d *Dialog) handle(resp *sip.Response) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Process based on response code
	switch {
	case resp.StatusCode >= 100 && resp.StatusCode < 200:
		// Provisional response
		if d.State == DialogStateTrying {
			d.State = DialogStateProceeding
			d.updateDialogStateInfo()
		} else if resp.StatusCode > 100 && d.State == DialogStateProceeding {
			// Check if we have a To tag - this is crucial for early dialog establishment
			toHeader := resp.To()
			if toHeader != nil {
				if toTag, hasTag := toHeader.Params.Get("tag"); hasTag && toTag != "" {
					// If we have a to-tag in a provisional response, transition to early dialog state
					d.State = DialogStateEarly
					d.SipInfo.RemoteTag = toTag
					d.updateDialogStateInfo()
				}
			}

			// Extract SDP if present in provisional response (early media)
			body := resp.Body()
			if len(body) > 0 {
				d.Remote.SDP = string(body)
			}
		}

	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Success response
		if d.State != DialogStateConfirmed {
			// Extract SDP if present
			body := resp.Body()
			if len(body) > 0 {
				d.Remote.SDP = string(body)
			}

			// Extract remote contact from Contact header
			contactHeader := resp.Contact()
			if contactHeader != nil {
				d.Remote.Contact = contactHeader.Address.String()
			}

			// Extract to tag from the response
			toHeader := resp.To()
			if toHeader != nil {
				if toTag, hasTag := toHeader.Params.Get("tag"); hasTag {
					d.SipInfo.RemoteTag = toTag
				}
			}

			// Check if this is a response to an INVITE request
			cseqHeader := resp.CSeq()
			if cseqHeader != nil && cseqHeader.MethodName == sip.INVITE {
				// Update state to confirmed
				d.State = DialogStateConfirmed
				d.pendingReinvite = false
				d.updateDialogStateInfo()

				// Important: Dialog is now established with a valid remoteTag
				// Store a copy of the mutex lock state to safely release it
				d.mu.Unlock()

				// After unlocking, notify observers
				if d.Type == DialogTypeUAC {
					// Only notify modify if this is a UAC dialog
					d.notifyObservers(DialogEventModify)
				}

				return
			}
		} else if d.pendingReinvite {
			// This is a response to a re-INVITE
			cseqHeader := resp.CSeq()
			if cseqHeader != nil && cseqHeader.MethodName == sip.INVITE {
				// Successful re-INVITE
				body := resp.Body()
				if len(body) > 0 {
					d.Remote.SDP = string(body)
				}

				d.pendingReinvite = false

				d.mu.Unlock()

				// After unlocking, notify observers
				d.notifyObservers(DialogEventModify)

				// Skip the deferred unlock since we've already unlocked
				return
			}
		}
	case resp.StatusCode >= 300:
		// Failure response
		if d.State != DialogStateConfirmed {
			if resp.StatusCode == 487 {
				// Request was cancelled
				d.State = DialogStateCancelled
			} else {
				// Other failure
				d.State = DialogStateRejected
			}
			d.updateDialogStateInfo()
			d.notifyObservers(DialogEventDestroy)
		} else if d.pendingReinvite {
			cseqHeader := resp.CSeq()
			if cseqHeader != nil && cseqHeader.MethodName == sip.INVITE {
				// Failed re-INVITE
				d.pendingReinvite = false
				// Notify about the failed re-INVITE
				d.notifyObservers(DialogEventModify)
			}
		}
	}
}

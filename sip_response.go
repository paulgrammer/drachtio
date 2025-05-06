package drachtio

import (
	"fmt"

	"github.com/emiago/sipgo/sip"
)

func (s *Srf) handleSIPResponse(resp *sip.Response, msg *InboundSIPRequest) {
	// Check if this response belongs to a dialog we know about
	dialogID := msg.DialogID
	transactionID := msg.TransactionID

	s.logger.Debug("Processing SIP response",
		"status", fmt.Sprintf("%d", resp.StatusCode),
		"transaction-id", transactionID,
		"dialog-id", dialogID)

	// First try by dialogID if provided
	if dialogID != "" {
		if dialog := s.DialogHandler.FindDialogById(dialogID); dialog != nil {
			// Found dialog by dialogID - store the server-provided transaction ID
			dialog.SetTransactionID(transactionID)

			// Process dialog-specific response handling
			// dialog.handleResponse(resp)

			// Also notify any request observers
			if dialog.req != nil {
				if req, ok := dialog.req.Message.(*sip.Request); ok {
					srfRes := NewSrfResponse(dialog.wp, req, msg)
					srfRes.WithResponse(resp)
					dialog.req.notifyResObservers(ResponseEvent, srfRes)
				}
			}
			return
		}
	}

	// Try by Call-ID and tags if dialog ID not found
	if resp.CallID() != nil && resp.From() != nil {
		callID := resp.CallID().Value()
		fromTag, hasFromTag := resp.From().Params.Get("tag")
		toTag, hasToTag := resp.To().Params.Get("tag")

		if hasFromTag {
			// Try to find dialog by Call-ID and From tag
			if dialog := s.DialogHandler.FindDialogByCallIDAndFromTag(callID, fromTag); dialog != nil {
				// Found dialog - store the transaction ID
				dialog.SetTransactionID(transactionID)

				// If dialog is in early state and we have a to-tag now, update it
				if dialog.State == DialogStateEarly || dialog.State == DialogStateProceeding {
					if hasToTag && dialog.SipInfo.RemoteTag == "" {
						dialog.mu.Lock()
						dialog.SipInfo.RemoteTag = toTag
						dialog.mu.Unlock()
					}
				}

				// Process dialog-specific response handling
				// dialog.handleResponse(resp)

				// Also notify any request observers
				if dialog.req != nil {
					if req, ok := dialog.req.Message.(*sip.Request); ok {
						srfRes := NewSrfResponse(dialog.wp, req, msg)
						srfRes.WithResponse(resp)
						dialog.req.notifyResObservers(ResponseEvent, srfRes)
					}
				}
				return
			}
		}
	}

	// Check if this is a response to an INVITE that could create a dialog
	if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		resp.CSeq() != nil && resp.CSeq().MethodName == sip.INVITE {
		// This might be the first 2xx response to an INVITE but we couldn't find the dialog
		// Log more details to help debug
		s.logger.Warn("Received 2xx response to INVITE but couldn't find matching dialog",
			"status", fmt.Sprintf("%d", resp.StatusCode),
			"transaction-id", transactionID,
			"dialog-id", dialogID,
			"call-id", resp.CallID().Value(),
			"cseq", fmt.Sprintf("%d %s", resp.CSeq().SeqNo, resp.CSeq().MethodName))
	}

	// If we got here, this is either a response to a non-dialog request
	// or we couldn't find the associated dialog
	s.logger.Debug("Unhandled SIP response",
		"status", fmt.Sprintf("%d", resp.StatusCode),
		"transaction-id", transactionID,
		"dialog-id", dialogID)
}
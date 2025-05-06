package drachtio

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/emiago/sipgo/sip"
)

// Common SIP/dialog error types
var (
	ErrDialogNotFound      = errors.New("dialog not found")
	ErrDialogAlreadyExists = errors.New("dialog already exists")
	ErrInvalidDialogState  = errors.New("invalid dialog state")
	ErrPendingReinvite     = errors.New("pending re-INVITE")
	ErrDialogTerminated    = errors.New("dialog already terminated")
	ErrNoRemoteTag         = errors.New("remote tag not present")
	ErrNoLocalTag          = errors.New("local tag not present")
	ErrNoCallID            = errors.New("Call-ID not present")
	ErrInvalidDialogType   = errors.New("invalid dialog type")
)

// SipErrorCode represents SIP status codes for errors
type SipErrorCode int

// SIP status codes
const (
	SipBadRequest           SipErrorCode = 400
	SipUnauthorized         SipErrorCode = 401
	SipForbidden            SipErrorCode = 403
	SipNotFound             SipErrorCode = 404
	SipMethodNotAllowed     SipErrorCode = 405
	SipRequestTimeout       SipErrorCode = 408
	SipConflict             SipErrorCode = 409
	SipTemporarilyUnavail   SipErrorCode = 480
	SipInternalServerError  SipErrorCode = 500
	SipServiceUnavailable   SipErrorCode = 503
	SipBusyEverywhere       SipErrorCode = 600
	SipDeclined             SipErrorCode = 603
)

// SipError represents a SIP protocol error with status code and reason
type SipError struct {
	Status int
	Reason string
	Res    *sip.Response // Optional reference to the response that caused the error
	Err    error         // Optional underlying error
	Code   SipErrorCode  // Optional error code for categorization
}

// Error implements the error interface
func (e SipError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("SIP Error %d: %s - %v", e.Status, e.Reason, e.Err)
	}
	return fmt.Sprintf("SIP Error %d: %s", e.Status, e.Reason)
}

// NewSipError creates a new SIP error with the given status code and reason
func NewSipError(status int, reason string) SipError {
	return SipError{
		Status: status,
		Reason: reason,
		Code:   SipErrorCode(status),
	}
}

// NewSipErrorWithCode creates a new SIP error with explicit code
func NewSipErrorWithCode(code SipErrorCode, reason string, err error) SipError {
	return SipError{
		Status: int(code),
		Reason: reason,
		Err:    err,
		Code:   code,
	}
}

// NewSipErrorFromResponse creates a new SIP error from a SIP response
func NewSipErrorFromResponse(resp *sip.Response) SipError {
	return SipError{
		Status: resp.StatusCode,
		Reason: resp.Reason,
		Res:    resp,
		Code:   SipErrorCode(resp.StatusCode),
	}
}

// IsTemporary returns true if the error is temporary and the operation could be retried
func (e SipError) IsTemporary() bool {
	switch e.Code {
	case SipRequestTimeout, SipTemporarilyUnavail, SipServiceUnavailable:
		return true
	default:
		return false
	}
}

// HTTPStatus returns the corresponding HTTP status code for this SIP error
func (e SipError) HTTPStatus() int {
	switch e.Code {
	case SipBadRequest:
		return http.StatusBadRequest
	case SipUnauthorized:
		return http.StatusUnauthorized
	case SipForbidden:
		return http.StatusForbidden
	case SipNotFound:
		return http.StatusNotFound
	case SipMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case SipRequestTimeout:
		return http.StatusRequestTimeout
	case SipConflict:
		return http.StatusConflict
	case SipInternalServerError:
		return http.StatusInternalServerError
	case SipServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// IsSipError checks if an error is a SipError
func IsSipError(err error) bool {
	_, ok := err.(SipError)
	return ok
}

// GetSipErrorCode extracts the SIP error code from an error, if present
func GetSipErrorCode(err error) (SipErrorCode, bool) {
	if sipErr, ok := err.(SipError); ok {
		return sipErr.Code, true
	}
	return 0, false
}
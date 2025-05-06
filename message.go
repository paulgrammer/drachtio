package drachtio

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// InboundResponse represents a response from the server.
type InboundResponse struct {
	MessageID string
	RequestID string
	Status    string
	Data      []string
	RawMsg    string
	Meta      *ResponseMeta
}

func (i *InboundResponse) ToInboundSIPRequest() *InboundSIPRequest {
	return &InboundSIPRequest{
		SourceAddress: i.Meta.Address,
		SourcePort:    i.Meta.Port,
		TransactionID: i.Meta.TransactionID,
		DialogID:      i.Meta.DialogID,
		SIPMessage:    i.RawMsg,
		TimeReceived:  i.Meta.Time,
		MessageID:     i.MessageID,
		ReceivedOn:    i.Meta.Time,
		Source:        i.Meta.Source,
	}
}

// ResponseMeta contains metadata for a response
type ResponseMeta struct {
	Source        string
	Address       string
	Port          string
	Protocol      string
	Time          string
	TransactionID string
	DialogID      string
}

// InboundSIPRequest represents an incoming SIP message from the server.
type InboundSIPRequest struct {
	MessageID     string
	Source        string
	Length        int
	Transport     string
	SourceAddress string
	SourcePort    string
	TimeReceived  string
	TransactionID string
	DialogID      string
	SIPMessage    string
	ReceivedOn    string
	Server        *ServerInfo
}

// ServerInfo represents server information
type ServerInfo struct {
	Address  string
	Hostport string
}

// IncomingCDREvent represents CDR events from the server.
type IncomingCDREvent struct {
	MessageID  string
	EventType  string // "attempt", "start", or "stop"
	Source     string
	Time       string
	CallID     string // Only for "start" and "stop" events
	SIPMessage string
}

type messageParser struct {
	logger *slog.Logger
	buffer []byte
}

func newMessageParser(logger *slog.Logger) *messageParser {
	return &messageParser{
		logger: logger,
		buffer: make([]byte, 0, 4096),
	}
}

func (p *messageParser) Read(reader *bufio.Reader) (WireResponse, error) {
	for {
		hashIdx := bytes.IndexByte(p.buffer, '#')
		if hashIdx > 0 {
			lengthStr := string(p.buffer[:hashIdx])
			msgLength, err := strconv.Atoi(lengthStr)
			if err != nil {
				p.logger.Error("Invalid message length", "error", err)
				p.buffer = p.buffer[hashIdx+1:]
				continue
			}

			start := hashIdx + 1
			end := start + msgLength
			if len(p.buffer) >= end {
				msg := p.buffer[start:end]
				p.buffer = p.buffer[end:]
				return p.parse(string(msg))
			}
		}

		buf := make([]byte, 1024)
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("read error: %w", err)
		}

		p.buffer = append(p.buffer, buf[:n]...)
	}
}

// parse parses a payload from the server into structured data.
func (p *messageParser) parse(payload string) (WireResponse, error) {
	pos := strings.Index(payload, DR_CRLF)
	if pos == -1 {
		// No CR found, treat the entire payload as the header
		pos = len(payload)
	}

	header := payload[:pos]
	tokens := strings.Split(header, "|")
	if len(tokens) < 2 {
		return nil, fmt.Errorf("invalid header line: insufficient tokens")
	}

	messageID := tokens[0]
	messageType := tokens[1]

	switch messageType {
	case "response":
		if len(tokens) < 4 {
			return nil, fmt.Errorf("invalid response message: expected at least 4 tokens")
		}

		var rawMsg string
		if pos != len(payload) {
			rawMsg = payload[pos+2:] // Skip CR+LF
		}

		var meta *ResponseMeta
		if len(tokens) >= 12 {
			meta = &ResponseMeta{
				Source:        tokens[4],
				Protocol:      tokens[6],
				Address:       tokens[7],
				Port:          tokens[8],
				Time:          tokens[9],
				TransactionID: tokens[10],
				DialogID:      tokens[11],
			}
		}

		return &InboundResponse{
			MessageID: messageID,
			RequestID: tokens[2],
			Status:    tokens[3],
			Data:      tokens[4:],
			RawMsg:    rawMsg,
			Meta:      meta,
		}, nil

	case "sip":
		if len(tokens) < 9 {
			return nil, fmt.Errorf("invalid SIP message header: expected at least 9 tokens")
		}

		length, err := strconv.Atoi(tokens[3])
		if err != nil {
			return nil, fmt.Errorf("invalid SIP message length: %v", err)
		}

		dialogID := ""
		if len(tokens) > 9 {
			dialogID = tokens[9]
		}

		// Extract SIP message content
		var sipMessage string
		if pos != len(payload) {
			sipMessage = payload[pos+2:] // Skip CR+LF
		}

		// Handle receivedOn field like in JS implementation
		var receivedOn string
		if len(tokens) > 11 {
			receivedOn = tokens[10] + ":" + tokens[11]
		}

		// Create server info if we have enough data
		var server *ServerInfo
		if len(tokens) > 5 {
			server = &ServerInfo{
				Address:  tokens[5], // Using sourceAddress as server address
				Hostport: tokens[5] + ":" + tokens[6],
			}
		}

		return &InboundSIPRequest{
			MessageID:     messageID,
			Source:        tokens[2],
			Length:        length,
			Transport:     tokens[4],
			SourceAddress: tokens[5],
			SourcePort:    tokens[6],
			TimeReceived:  tokens[7],
			TransactionID: tokens[8],
			DialogID:      dialogID,
			SIPMessage:    sipMessage,
			ReceivedOn:    receivedOn,
			Server:        server,
		}, nil

	case "cdr:attempt", "cdr:start", "cdr:stop":
		if len(tokens) < 4 {
			return nil, fmt.Errorf("invalid CDR message: expected at least 4 tokens")
		}

		eventType := strings.Split(messageType, ":")[1] // Extract "attempt", "start", or "stop"
		source := tokens[2]
		timestamp := tokens[3]

		callID := ""
		if eventType != "attempt" && len(tokens) > 4 {
			callID = tokens[4]
		}

		var sipMessage string
		if pos != len(payload) {
			sipMessage = payload[pos+2:] // Skip CR+LF
		}

		return &IncomingCDREvent{
			MessageID:  messageID,
			EventType:  eventType,
			Source:     source,
			Time:       timestamp,
			CallID:     callID,
			SIPMessage: sipMessage,
		}, nil

	default:
		return nil, fmt.Errorf("unknown message type: %s", messageType)
	}
}

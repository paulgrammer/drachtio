package drachtio

import (
	"sync"
)

type callbackManager struct {
	callbacks sync.Map
}

func newCallbackManager() *callbackManager {
	return &callbackManager{}
}

func (m *callbackManager) Register(reqID string, ch chan *InboundResponse) {
	m.callbacks.Store(reqID, ch)
}

func (m *callbackManager) Unregister(reqID string) {
	m.callbacks.Delete(reqID)
}

func (m *callbackManager) Handle(msg WireResponse) *InboundResponse {
	if resp, ok := msg.(*InboundResponse); ok {
		if ch, exists := m.callbacks.Load(resp.RequestID); exists {
			ch.(chan *InboundResponse) <- resp
			return resp
		}
	}

	return nil
}

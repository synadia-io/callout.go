package callout

import (
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
)

type ServiceMsgAdapter struct {
	msg   *nats.Msg
	noNet bool
}

func NewNoNetServiceMsgAdapter(m *nats.Msg) *ServiceMsgAdapter {
	return &ServiceMsgAdapter{msg: m, noNet: true}
}

func NewServiceMsgAdapter(m *nats.Msg) *ServiceMsgAdapter {
	return &ServiceMsgAdapter{msg: m, noNet: false}
}

func (m *ServiceMsgAdapter) Respond([]byte, ...micro.RespondOpt) error {
	if m.noNet {
		return nil
	}
	return m.msg.Respond(m.msg.Data)
}

func (m *ServiceMsgAdapter) RespondJSON(any, ...micro.RespondOpt) error {
	if m.noNet {
		return nil
	}
	return m.msg.Respond(m.msg.Data)
}

func (m *ServiceMsgAdapter) Error(code, description string, data []byte, opts ...micro.RespondOpt) error {
	return nil
}

// Data returns request data.
func (m *ServiceMsgAdapter) Data() []byte {
	return m.msg.Data
}

// Headers returns request headers.
func (m *ServiceMsgAdapter) Headers() micro.Headers {
	return nil
}

// Subject returns underlying NATS message subject.
func (m *ServiceMsgAdapter) Subject() string {
	return m.msg.Subject
}

func (m *ServiceMsgAdapter) Reply() string {
	return m.msg.Reply
}

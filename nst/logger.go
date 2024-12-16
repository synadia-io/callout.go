package nst

import (
	nslogger "github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats-server/v2/server"
)

type TestLogger struct {
	logger server.Logger
}

func NewTestLogger() server.Logger {
	logger := nslogger.NewStdLogger(true, true, true, true, true)
	return &TestLogger{
		logger: logger,
	}
}

func (l *TestLogger) Noticef(format string, v ...interface{}) {}
func (l *TestLogger) Warnf(format string, v ...interface{})   {}
func (l *TestLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatalf(format, v...)
}

func (l *TestLogger) Errorf(format string, v ...interface{}) {
	l.logger.Errorf(format, v...)
}
func (l *TestLogger) Debugf(format string, v ...interface{}) {}
func (l *TestLogger) Tracef(format string, v ...interface{}) {}

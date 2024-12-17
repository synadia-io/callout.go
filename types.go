package callout

import (
	"fmt"

	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
)

const (
	NatsServerXKeyHeader = "Nats-Server-Xkey"
	ExpectedAudience     = "nats-authorization-request"
)

// Authorizer is a callback to AuthorizationService returns a user JWT
type Authorizer func(req *jwt.AuthorizationRequest) (string, error)

// AuthorizerErrCallback this is an optional callback that gets invoked whenever the Authorizer
// returns an error, this is useful for tests
type AuthorizerErrCallback func(err error)

type ResponseSigner func(*jwt.AuthorizationResponseClaims) (string, error)

func AuthorizationService(
	nc *nats.Conn,
	authorizer Authorizer,
	keys *Keys,
	Logger natsserver.Logger,
	errFn AuthorizerErrCallback,
	responseSignerFn ResponseSigner,
) (micro.Service, error) {
	if Logger == nil {
		Logger = nslogger.NewStdLogger(true, true, true, true, true)
	}

	if authorizer == nil {
		return nil, fmt.Errorf("authorizer is required")
	}

	if keys == nil {
		return nil, fmt.Errorf("keys is required")
	}

	if err := keys.Valid(responseSignerFn != nil); err != nil {
		return nil, err
	}

	callout := &Callout{
		authorizer:       authorizer,
		keys:             keys,
		logger:           Logger,
		errFn:            errFn,
		responseSignerFn: responseSignerFn,
	}

	config := micro.Config{
		Name:        "auth",
		Version:     "0.0.1",
		Description: "AuthCallout Authorization Service",
		DoneHandler: func(srv micro.Service) {
			info := srv.Info()
			Logger.Warnf("stopped service %q with ID %q\n", info.Name, info.ID)
		},
		ErrorHandler: func(srv micro.Service, err *micro.NATSError) {
			info := srv.Info()
			Logger.Errorf("service %q returned an error on subject %q: %s", info.Name, err.Subject, err.Description)
		},
		Endpoint: &micro.EndpointConfig{
			Subject: "$SYS.REQ.USER.AUTH",
			Handler: micro.HandlerFunc(callout.ServiceHandler),
		},
	}

	srv, err := micro.AddService(nc, config)
	if err != nil {
		Logger.Fatalf("failed to add service: %s", err)
	}
	Logger.Noticef("authorization service started: %s", nc.ConnectedUrl())
	callout.service = srv
	return srv, err
}

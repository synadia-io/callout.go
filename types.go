package callout

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nkeys"

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

// ErrCallback this is an optional callback that gets invoked whenever the Authorizer
// returns an error, this is useful for tests
type ErrCallback func(err error)

// ResponseSignerFn allows externalizing the signing to a different workflow
// where the callout doesn't directly sign the jwt.AuthorizationResponseClaims
// but instead forwards the request to some other mechanism
type ResponseSignerFn func(*jwt.AuthorizationResponseClaims) (string, error)

type Keys struct {
	// ResponseSigner is the key that will be used to sign the jwt.AuthorizationResponseClaim
	ResponseSignerKey nkeys.KeyPair
	// ResponseSigner is the key that ID of the account issuing the jwt.AuthorizationResponseClaim
	// if not set, ResponseSigner is the account
	ResponseSignerIssuer string
	// EncryptionKey is an optional configuration that must be provided if the
	// callout is configured to use encryption.
	EncryptionKey nkeys.KeyPair
}

type Options struct {
	Keys
	Authorizer     Authorizer
	Logger         natsserver.Logger
	ErrorFn        ErrCallback
	ResponseSigner ResponseSignerFn
}

type Option func(*Options) error

func AuthorizerFn(fn Authorizer) Option {
	return func(o *Options) error {
		o.Authorizer = fn
		return nil
	}
}

func Logger(l natsserver.Logger) Option {
	return func(o *Options) error {
		o.Logger = l
		return nil
	}
}

func ErrCallbackFn(fn ErrCallback) Option {
	return func(o *Options) error {
		o.ErrorFn = fn
		return nil
	}
}

func ResponseSignerKey(kp nkeys.KeyPair) Option {
	return func(o *Options) error {
		o.ResponseSignerKey = kp
		return nil
	}
}

func ResponseSigner(fn ResponseSignerFn) Option {
	return func(o *Options) error {
		o.ResponseSigner = fn
		return nil
	}
}

func ResponseSignerIssuer(pub string) Option {
	return func(o *Options) error {
		if strings.HasPrefix(pub, "SA") {
			kp, err := nkeys.FromSeed([]byte(pub))
			if err != nil {
				return err
			}
			pub, err = kp.PublicKey()
			if err != nil {
				return err
			}
		} else if strings.HasPrefix(pub, "A") {
			_, err := nkeys.FromPublicKey(pub)
			if err != nil {
				return err
			}
		} else {
			return errors.New("account public key required")
		}
		o.ResponseSignerIssuer = pub
		return nil
	}
}

func EncryptionKey(kp nkeys.KeyPair) Option {
	return func(o *Options) error {
		o.EncryptionKey = kp
		seed, err := kp.Seed()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(seed), "SC") {
			return errors.New("curve seed required")
		}
		return nil
	}
}

func AuthorizationService(
	nc *nats.Conn, opts ...Option,
) (micro.Service, error) {
	options := &Options{}
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	if options.Logger == nil {
		options.Logger = nslogger.NewStdLogger(true, true, true, true, true)
	}

	if options.Authorizer == nil {
		return nil, fmt.Errorf("authorizer is required")
	}

	callout := &Callout{opts: options}

	config := micro.Config{
		Name:        "auth",
		Version:     "0.0.1",
		Description: "AuthCallout Authorization Service",
		DoneHandler: func(srv micro.Service) {
			info := srv.Info()
			options.Logger.Warnf("stopped service %q with ID %q\n", info.Name, info.ID)
		},
		ErrorHandler: func(srv micro.Service, err *micro.NATSError) {
			info := srv.Info()
			options.Logger.Errorf("service %q returned an error on subject %q: %s", info.Name, err.Subject, err.Description)
		},
		Endpoint: &micro.EndpointConfig{
			Subject: "$SYS.REQ.USER.AUTH",
			Handler: micro.HandlerFunc(callout.ServiceHandler),
		},
	}

	srv, err := micro.AddService(nc, config)
	if err != nil {
		options.Logger.Fatalf("failed to add service: %s", err)
	}
	options.Logger.Noticef("authorization service started: %s", nc.ConnectedUrl())
	callout.service = srv
	return srv, err
}

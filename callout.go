package callout

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	nslogger "github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/micro"
)

// ErrAbortRequest is an internal Error that signals for operation to abort
var ErrAbortRequest = errors.New("abort request")

type Callout struct {
	opts    *Options
	service micro.Service
}

const (
	NatsServerXKeyHeader   = "Nats-Server-Xkey"
	ExpectedAudience       = "nats-authorization-request"
	SysRequestUserAuthSubj = "$SYS.REQ.USER.AUTH"
)

// Authorizer is a callback to AuthorizationService returns a user JWT
type Authorizer func(req *jwt.AuthorizationRequest) (string, error)

// ErrCallback this is an optional callback that gets invoked whenever the Authorizer
// returns an error, this is useful for tests
type ErrCallback func(err error)

type InvalidUserCallback func(jwt string, err error)

// ResponseSignerFn allows externalizing the signing to a different workflow
// where the callout doesn't directly sign the jwt.AuthorizationResponseClaims
// but instead forwards the request to some other mechanism
type ResponseSignerFn func(*jwt.AuthorizationResponseClaims) (string, error)

type Options struct {
	// Authorizer function that processes authorization request and issues user JWT
	Authorizer Authorizer
	// ResponseSigner is a function that performs the signing of the jwt.AuthorizationResponseClaim
	ResponseSigner ResponseSignerFn
	// ResponseSigner is the key that will be used to sign the jwt.AuthorizationResponseClaim
	ResponseSignerKey nkeys.KeyPair
	// ResponseSigner is the key that ID of the account issuing the jwt.AuthorizationResponseClaim
	// if not set, ResponseSigner is the account
	ResponseSignerIssuer string
	// EncryptionKey is an optional configuration that must be provided if the
	// callout is configured to use encryption.
	EncryptionKey nkeys.KeyPair
	// Logger for the service process
	Logger natsserver.Logger
	// InvalidUser when set user JWTs are validated if error
	// notified via the callback
	InvalidUser InvalidUserCallback
}

type Option func(*Options) error

func processOptions(opts ...Option) (*Options, error) {
	options := &Options{}
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}
	return options, nil
}

func AuthorizationService(
	nc *nats.Conn, opts ...Option,
) (micro.Service, error) {
	options, err := processOptions(opts...)
	if err != nil {
		return nil, err
	}

	if options.Logger == nil {
		options.Logger = nslogger.NewStdLogger(true, true, true, true, true)
	}
	if options.Authorizer == nil {
		return nil, fmt.Errorf("authorizer is required")
	}
	if options.ResponseSigner != nil && (options.ResponseSignerKey != nil || options.ResponseSignerIssuer != "") {
		return nil, fmt.Errorf("response signer and response signer key/issuer are mutually exclusive")
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
			Subject: SysRequestUserAuthSubj,
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

func (c *Callout) decode(msg micro.Request) (bool, *jwt.AuthorizationRequest, error) {
	isEncrypted := false
	data := msg.Data()
	if len(data) < 4 {
		return false, nil, fmt.Errorf("expected a payload")
	}
	// if we don't have the "eyJ0" this is not a JWT
	if !bytes.HasPrefix(data, []byte{'e', 'y', 'J', '0'}) {
		isEncrypted = true
	}

	// checkKey misconfiguration
	if c.opts.EncryptionKey != nil && !isEncrypted {
		c.opts.Logger.Errorf("configuration mismatch: service requires encryption but server doesn't")
		return true, nil, ErrAbortRequest
	}
	if c.opts.EncryptionKey == nil && isEncrypted {
		c.opts.Logger.Errorf("configuration mismatch: service does not require encryption but server does")
		return true, nil, ErrAbortRequest
	}

	var serverKey string
	if c.opts.EncryptionKey != nil {
		serverKey = msg.Headers().Get(NatsServerXKeyHeader)
		dd, err := c.opts.EncryptionKey.Open(data, serverKey)
		if err != nil {
			c.opts.Logger.Errorf("error decrypting message: %w", err)
			return true, nil, ErrAbortRequest
		}
		data = dd
	}

	arc, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		c.opts.Logger.Errorf("error decoding auth request: %q: %w", string(data), err)
		return isEncrypted, nil, ErrAbortRequest
	}
	if arc.Audience != ExpectedAudience {
		c.opts.Logger.Errorf("error unexpected audience: %q", arc.Audience)
		return isEncrypted, nil, ErrAbortRequest
	}

	return isEncrypted, &arc.AuthorizationRequest, nil
}

func (c *Callout) sendResponse(msg micro.Request, isEncrypted bool, req *jwt.AuthorizationRequest, resp *jwt.AuthorizationResponseClaims) error {
	var token string
	var err error
	if c.opts.ResponseSigner != nil {
		token, err = c.opts.ResponseSigner(resp)
	} else {
		token, err = resp.Encode(c.opts.ResponseSignerKey)
	}
	if err != nil {
		return fmt.Errorf("error encoding response for %s: %w", req.UserNkey, err)
	}
	data := []byte(token)
	if isEncrypted {
		data, err = c.opts.EncryptionKey.Seal([]byte(token), req.Server.XKey)
		if err != nil {
			return fmt.Errorf("error encrypting response for %s: %w", req.UserNkey, err)
		}
	}
	// use micro response/error so the metrics are meaningful
	if resp.Error != "" {
		if err := msg.Error("401", "unauthorized", data); err != nil {
			return err
		}
	} else {
		if err = msg.Respond(data); err != nil {
			return err
		}
	}
	return nil
}

func (c *Callout) ServiceHandler(msg micro.Request) {
	start := time.Now()
	isEncrypted, req, err := c.decode(msg)
	if err != nil {
		if !errors.Is(err, ErrAbortRequest) {
			c.opts.Logger.Errorf("error decoding request: %w", err)
		}
		return
	}
	if req == nil {
		c.opts.Logger.Errorf("failed to decode request: empty payload")
		return
	}

	defer func() {
		c.opts.Logger.Tracef("authorization for %s took %v", req.UserNkey, time.Since(start))
	}()

	// prepare the response
	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID
	if c.opts.ResponseSignerIssuer != "" {
		// key already validated
		resp.IssuerAccount = c.opts.ResponseSignerIssuer
	}
	// authorize
	user, err := c.opts.Authorizer(req)
	resp.Jwt = user
	// if we don't have a user nor an error - callout failed to do the right thing, put an error
	if user == "" && err == nil {
		c.opts.Logger.Errorf("error authorizing %s: authorizer didn't generate a JWT", req.UserNkey)
		return
	}
	// if we have an error, send the error - unless we get an ErrAbortRequest
	if err != nil {
		if errors.Is(err, ErrAbortRequest) {
			return
		}
		resp.Error = err.Error()
	}

	if user != "" && c.opts.InvalidUser != nil {
		// run some validation checks to help debugging service - these don't stop the service
		// just simply help getting an audit
		uc, err := jwt.DecodeUserClaims(user)
		if err != nil {
			c.opts.InvalidUser(user, err)
		}
		if err == nil {
			vr := &jwt.ValidationResults{}
			uc.Validate(vr)
			errs := vr.Errors()
			if len(errs) > 0 {
				c.opts.InvalidUser(user, errors.Join(errs...))
			}
		}
	}

	if err := c.sendResponse(msg, isEncrypted, req, resp); err != nil {
		c.opts.Logger.Errorf("error sending response: %w", err)
	}
}

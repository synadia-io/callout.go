package callout

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
)

type RequestContextError struct {
	UserID string
	Reason error
}

func (r RequestContextError) Error() string {
	return fmt.Sprintf("request failed for %s: %s", r.UserID, r.Reason.Error())
}

func (r RequestContextError) Unwrap() error {
	return r.Reason
}

func (r RequestContextError) User() string {
	return r.UserID
}

// ErrAbortRequest is an Error that signals for operation to abort.
// Aborted operations don't respond to the callout request. Reason for
// aborting is to allow the NATS server to delay the connection error response
// and thus delay any possible denial-of-service attack.
var (
	ErrAbortRequest       = errors.New("abort request")
	ErrAuthorizerRequired = errors.New("authorizer is required")
	ErrBadCalloutOption   = errors.New("bad options")
	ErrService            = errors.New("service error")
	ErrRejectedAuth       = errors.New("rejected authorization request")
)

type Callout struct {
	opts    *Options
	service micro.Service
}

const (
	NatsServerXKeyHeader   = "Nats-Server-Xkey"
	ExpectedAudience       = "nats-authorization-request"
	SysRequestUserAuthSubj = "$SYS.REQ.USER.AUTH"
)

// AuthorizerFn is a callback to AuthorizationService returns a user JWT
type AuthorizerFn func(req *jwt.AuthorizationRequest) (string, error)

// ErrCallbackFn this is an optional callback that gets invoked whenever the
// AuthorizerFn
// returns an error, this is useful for tests
type ErrCallbackFn func(err error)

// InvalidUserCallbackFn is a function type invoked when a user JWT validation fails,
// providing the JWT and the error details.
type InvalidUserCallbackFn func(jwt string, err error)

// ResponseSignerFn allows externalizing the signing to a different workflow
// where the callout doesn't directly sign the jwt.AuthorizationResponseClaims
// but instead forwards the request to some other mechanism
type ResponseSignerFn func(*jwt.AuthorizationResponseClaims) (string, error)

// Options defines a configuration struct for handling authorization and signing of
// user JWTs within a service.
type Options struct {
	// Authorizer function that processes authorization request and issues user JWT
	Authorizer AuthorizerFn
	// ResponseSigner is a function that performs the signing of the
	// jwt.AuthorizationResponseClaim
	ResponseSigner ResponseSignerFn
	// ResponseSigner is the key that will be used to sign the
	// jwt.AuthorizationResponseClaim
	ResponseSignerKey nkeys.KeyPair
	// ResponseSigner is the key that ID of the account issuing the
	// jwt.AuthorizationResponseClaim
	// if not set, ResponseSigner is the account
	ResponseSignerIssuer string
	// EncryptionKey is an optional configuration that must be provided if the
	// callout is configured to use encryption.
	EncryptionKey nkeys.KeyPair
	// Logger for the service process
	Logger natsserver.Logger
	// InvalidUser when set user JWTs are validated if error
	// notified via the callback
	InvalidUser InvalidUserCallbackFn

	ErrCallback ErrCallbackFn

	ServiceWorkers int
}

// Option is a function type used to configure the Callout options
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

// AuthorizationService starts and configures an authorization microservice using
// NATS messaging system. Returns the created microservice instance and error
// if any issue occurs during setup.
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
		return nil, ErrAuthorizerRequired
	}
	if options.ResponseSigner != nil &&
		(options.ResponseSignerKey != nil || options.ResponseSignerIssuer != "") {
		return nil, errors.Join(
			ErrBadCalloutOption,
			errors.New(
				"response signer and response signer key/issuer are mutually exclusive",
			),
		)
	}
	if options.ErrCallback == nil {
		options.ErrCallback = func(err error) {
			options.Logger.Errorf(err.Error())
		}
	} else {
		userFn := options.ErrCallback
		options.ErrCallback = func(err error) {
			options.Logger.Errorf(err.Error())
			userFn(err)
		}
	}

	callout := &Callout{opts: options}

	config := micro.Config{
		Name:        "auth",
		Version:     "0.0.1",
		Description: "AuthCallout Authorization Service",
		DoneHandler: func(srv micro.Service) {
			info := srv.Info()
			options.Logger.Warnf(
				"stopped service %q with ID %q\n",
				info.Name,
				info.ID,
			)
		},
		ErrorHandler: func(srv micro.Service, err *micro.NATSError) {
			wErr := errors.Join(ErrService, err)
			callout.opts.ErrCallback(wErr)
		},
		Endpoint: &micro.EndpointConfig{
			Subject: SysRequestUserAuthSubj,
			Handler: micro.HandlerFunc(callout.ServiceHandler),
		},
	}

	srv, err := micro.AddService(nc, config)
	if err != nil {
		wErr := errors.Join(ErrService, fmt.Errorf("failed to add service: %w", err))
		options.ErrCallback(wErr)
		return nil, wErr
	}
	for i := 1; i < options.ServiceWorkers; i++ {
		if err = srv.AddEndpoint(fmt.Sprintf("w%d", i),
			micro.HandlerFunc(callout.ServiceHandler),
			micro.WithEndpointSubject(SysRequestUserAuthSubj)); err != nil {
			break
		}
		options.Logger.Noticef("added additional endpoint: %d", i+1)

	}
	if err != nil {
		_ = srv.Stop()
		wErr := errors.Join(ErrService, fmt.Errorf("failed to add endpoint: %w", err))
		options.ErrCallback(wErr)
		options.Logger.Errorf("authorization service failed to start: %s", err.Error())
		return nil, wErr
	}
	options.Logger.Noticef("authorization service started: %s", nc.ConnectedUrl())
	callout.service = srv
	return srv, err
}

// decode processes an incoming `micro.Request`, validates and decodes its payload,
// and detects if it is encrypted. It checks configuration mismatches for encryption
// and decrypts the data if necessary using the provided encryption key.
// The method ensures the payload contains a valid JWT Authorization Request with an
// expected audience. Returns a boolean indicating encryption, the decoded
// AuthorizationRequest if successful, and an error if any.
func (c *Callout) decode(
	msg micro.Request,
) (bool, *jwt.AuthorizationRequest, error) {
	isEncrypted := false
	data := msg.Data()
	if len(data) < 4 {
		wErr := errors.Join(
			fmt.Errorf("bad request: payload too short: %d", len(data)),
			ErrAbortRequest,
		)
		return false, nil, wErr
	}
	// if we don't have the "eyJ0" this is not a JWT
	if !bytes.HasPrefix(data, []byte{'e', 'y', 'J', '0'}) {
		isEncrypted = true
	}

	// checkKey misconfiguration
	if c.opts.EncryptionKey != nil && !isEncrypted {
		wErr := errors.Join(
			fmt.Errorf("bad request: encryption mismatch: payload is not encrypted"),
			ErrAbortRequest,
		)
		return true, nil, wErr
	}
	if c.opts.EncryptionKey == nil && isEncrypted {
		wErr := errors.Join(
			fmt.Errorf("bad request: encryption mismatch: payload is encrypted"),
			ErrAbortRequest,
		)
		return true, nil, wErr
	}

	var serverKey string
	if c.opts.EncryptionKey != nil {
		serverKey = msg.Headers().Get(NatsServerXKeyHeader)
		dd, err := c.opts.EncryptionKey.Open(data, serverKey)
		if err != nil {
			wErr := errors.Join(
				fmt.Errorf("bad request: error decrypting message: %w", err),
				ErrAbortRequest,
			)
			return true, nil, wErr
		}
		data = dd
	}

	arc, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		wErr := errors.Join(
			fmt.Errorf("bad request: error decoding auth request: %w", err),
			ErrAbortRequest,
		)
		return isEncrypted, nil, wErr
	}
	if !bytes.HasPrefix([]byte(arc.Issuer), []byte{'N'}) {
		wErr := errors.Join(
			fmt.Errorf("bad request: expected server: %q", arc.Issuer),
			ErrAbortRequest,
		)
		return isEncrypted, nil, wErr
	}
	if arc.Issuer != arc.Server.ID {
		wErr := errors.Join(
			fmt.Errorf("bad request: issuers don't match: %q != %q", arc.Audience, arc.Server.ID),
			ErrAbortRequest,
		)
		return isEncrypted, nil, wErr
	}
	if arc.Audience != ExpectedAudience {
		wErr := errors.Join(
			fmt.Errorf("bad request: unexpected audience: %q", arc.Audience),
			ErrAbortRequest,
		)
		return isEncrypted, nil, wErr
	}

	return isEncrypted, &arc.AuthorizationRequest, nil
}

// sendResponse formats and sends a response or error to a micro.Request based on
// provided AuthorizationRequest and ResponseClaims. It signs the response or encodes
// it using the provided signing key and encrypts it if required using the encryption
// key. Returns an error if signing, encoding, encrypting, or responding fails.
func (c *Callout) sendResponse(
	msg micro.Request,
	isEncrypted bool,
	req *jwt.AuthorizationRequest,
	resp *jwt.AuthorizationResponseClaims,
) error {
	var token string
	var err error
	if c.opts.ResponseSigner != nil {
		token, err = c.opts.ResponseSigner(resp)
	} else {
		token, err = resp.Encode(c.opts.ResponseSignerKey)
	}
	if err != nil {
		wErr := RequestContextError{Reason: err, UserID: req.UserNkey}
		c.opts.ErrCallback(wErr)
		return wErr
	}
	data := []byte(token)
	if isEncrypted {
		data, err = c.opts.EncryptionKey.Seal([]byte(token), req.Server.XKey)
		if err != nil {
			wErr := RequestContextError{Reason: err, UserID: req.UserNkey}
			c.opts.ErrCallback(wErr)
			return wErr
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

// ServiceHandler processes an incoming micro.Request to decode, validate, and
// authorize the payload, and sends a proper response.
func (c *Callout) ServiceHandler(msg micro.Request) {
	start := time.Now()
	isEncrypted, req, err := c.decode(msg)
	if err != nil {
		c.opts.ErrCallback(err)
		if errors.Is(err, ErrAbortRequest) {
			return
		}
	} else if req == nil {
		err = errors.Join(fmt.Errorf("bad request: empty payload"), ErrAbortRequest)
		c.opts.ErrCallback(err)
		return
	}

	defer func() {
		c.opts.Logger.Tracef(
			"authorization for %s took %v",
			req.UserNkey,
			time.Since(start),
		)
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
	// if we don't have a user nor an error - callout failed to do the right thing,
	// put an error
	if user == "" && err == nil {
		wErr := errors.Join(RequestContextError{
			Reason: fmt.Errorf(
				"error authorizing: authorizer didn't generate a JWT",
			),
			UserID: req.UserNkey,
		}, ErrAbortRequest)
		c.opts.ErrCallback(wErr)
		return
	}
	// if we have an error, send the error - unless we get an ErrAbortRequest
	if err != nil {
		if errors.Is(err, ErrAbortRequest) {
			wErr := RequestContextError{Reason: err, UserID: req.UserNkey}
			c.opts.ErrCallback(wErr)
			return
		}
		wErr := errors.Join(
			RequestContextError{Reason: err, UserID: req.UserNkey},
			ErrRejectedAuth,
		)
		c.opts.ErrCallback(wErr)
		resp.Error = err.Error()
	}

	if user != "" && c.opts.InvalidUser != nil {
		// run some validation checks to help debugging service - these don't stop
		// the service just simply help getting an audit, connection will fail on
		// the server with Authorization Error
		uc, err := jwt.DecodeUserClaims(user)
		if err != nil {
			c.opts.InvalidUser(user, err)
		}
		if err == nil {
			vr := &jwt.ValidationResults{}
			uc.Validate(vr)
			errs := vr.Errors()
			if len(errs) > 0 {
				err = errors.Join(errs...)
				c.opts.InvalidUser(user, err)
			}
		}
		if err != nil {
			wErr := errors.Join(
				RequestContextError{
					Reason: fmt.Errorf("error validating jwt: %w", err),
					UserID: req.UserNkey,
				},
			)
			c.opts.ErrCallback(wErr)
		}
	}

	if err := c.sendResponse(msg, isEncrypted, req, resp); err != nil {
		wErr := errors.Join(
			RequestContextError{
				Reason: fmt.Errorf("error publishing response: %w", err),
				UserID: req.UserNkey,
			},
		)
		c.opts.ErrCallback(wErr)
	}
}

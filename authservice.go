// Copyright 2025 Synadia Communications, Inc
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callout

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
)

// RequestContextError represents an error in the context of handling a user
// request, including the user ID and the cause.
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

var (
	// ErrAbortRequest is an Error that signals for operation to abort.
	// Aborted operations don't respond to the callout request. Reason for
	// aborting is to allow the NATS server to delay the connection error
	// response and thus delay any possible denial-of-service attack.
	ErrAbortRequest = errors.New("abort request")
	// ErrAuthorizerRequired indicates that an authorizer must be provided for
	// the operation to proceed.
	ErrAuthorizerRequired = errors.New("authorizer is required")
	// ErrBadCalloutOption indicates an invalid or incompatible configuration
	// option was provided to NewAuthorizationService.
	ErrBadCalloutOption = errors.New("bad options")
	// ErrService represents a general service error that may occur during
	// operation execution.
	ErrService = errors.New("service error")
	// ErrRejectedAuth indicates that an authorization request was explicitly
	// rejected, typically due to invalid credentials or other authorization
	// failures.
	ErrRejectedAuth = errors.New("rejected authorization request")
)

const (
	NatsServerXKeyHeader   = "Nats-Server-Xkey"
	ExpectedAudience       = "nats-authorization-request"
	SysRequestUserAuthSubj = "$SYS.REQ.USER.AUTH"
)

// AuthorizerFn is a callback to AuthorizationService returns a user JWT
type AuthorizerFn func(req *jwt.AuthorizationRequest) (string, error)

// ErrCallbackFn this is an optional callback that gets invoked whenever the
// AuthorizerFn returns an error, this is useful for tests
type ErrCallbackFn func(err error)

// InvalidUserCallbackFn is a function type invoked when a user JWT validation
// fails, providing the JWT and the error details.
type InvalidUserCallbackFn func(jwt string, err error)

// ResponseSignerFn allows externalizing the signing to a different workflow where
// the callout doesn't directly sign the jwt.AuthorizationResponseClaims but
// instead forwards the request to some other mechanism
type ResponseSignerFn func(*jwt.AuthorizationResponseClaims) (string, error)

// Options defines a configuration struct for handling authorization and signing of
// user JWTs within a service.
type Options struct {
	// Name for the AuthorizationService cannot have spaces, etc, as this is
	// the name that the actual micro.Service will use.
	Name string
	// Authorizer function that processes authorization request and issues user
	// JWT
	Authorizer AuthorizerFn
	// ResponseSigner is a function that performs the signing of the
	// jwt.AuthorizationResponseClaim
	ResponseSigner ResponseSignerFn
	// ResponseSigner is the key that will be used to sign the
	// jwt.AuthorizationResponseClaim
	ResponseSignerKey nkeys.KeyPair
	// ResponseSigner is the key that ID of the account issuing the
	// jwt.AuthorizationResponseClaim if not set, ResponseSigner is the account
	ResponseSignerIssuer string
	// EncryptionKey is an optional configuration that must be provided if the
	// callout is configured to use encryption.
	EncryptionKey nkeys.KeyPair
	// Logger for the service process
	Logger natsserver.Logger
	// InvalidUser when set user JWTs are validated if error notified via the
	// callback
	InvalidUser InvalidUserCallbackFn
	// ErrCallback is an optional callback invoked whenever AuthorizerFn
	// returns an error, useful for handling test errors.
	ErrCallback ErrCallbackFn
	// ServiceEndpoints sets the number of endpoints available for the service
	// to handle requests.
	ServiceEndpoints int
	// AsyncWorkers specifies the number of workers used for asynchronous task
	// processing.
	AsyncWorkers int
}

// Option is a function type used to configure the AuthorizationService options
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

// AuthorizationService is a service that handles user authorization requests and
// processes JWT-based authentication.  It uses options to specify configuration
// such as authorizers, response signers, encryption keys, and logging.  The
// service can operate with synchronous or asynchronous request handling using
// worker channels.
type AuthorizationService struct {
	opts      *Options
	Service   micro.Service
	workersCh chan micro.Request
	wg        sync.WaitGroup
}

// NewAuthorizationService initializes and returns a new instance of
// AuthorizationService with the provided options.  It sets up the service,
// including logging, error handling, and request-processing functionality.
//
//	Errors may occur during initialization due to missing or incompatible options.
//
//	Returns an AuthorizationService instance and an error, if any occurred.
func NewAuthorizationService(
	nc *nats.Conn, opts ...Option,
) (*AuthorizationService, error) {
	options, err := processOptions(opts...)
	if err != nil {
		return nil, err
	}
	if options.Name == "" {
		options.Name = "auth"
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

	callout := &AuthorizationService{opts: options}

	if options.AsyncWorkers > 0 {
		callout.workersCh = make(chan micro.Request, 5000)
		for i := 0; i < options.AsyncWorkers; i++ {
			go func() {
				callout.wg.Add(1)
				defer callout.wg.Done()
				for {
					select {
					case msg, ok := <-callout.workersCh:
						if !ok {
							return
						}
						callout.ServiceHandler(msg)
					}
				}
			}()
		}
	}

	config := micro.Config{
		Name:        options.Name,
		Version:     "0.0.1",
		Description: "Authorization Service",
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
	}

	if options.AsyncWorkers > 0 {
		config.Endpoint = &micro.EndpointConfig{
			Subject: SysRequestUserAuthSubj,
			Handler: micro.HandlerFunc(callout.AsyncWorkerHandler),
		}
	} else {
		config.Endpoint = &micro.EndpointConfig{
			Subject: SysRequestUserAuthSubj,
			Handler: micro.HandlerFunc(callout.ServiceHandler),
		}
	}

	srv, err := micro.AddService(nc, config)
	if err != nil {
		wErr := errors.Join(ErrService, fmt.Errorf("failed to add service: %w", err))
		options.ErrCallback(wErr)
		return nil, wErr
	}
	for i := 1; i < options.ServiceEndpoints; i++ {
		fn := callout.ServiceHandler
		if err = srv.AddEndpoint(fmt.Sprintf("w%d", i),
			micro.HandlerFunc(fn),
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
	callout.Service = srv
	return callout, err
}

// Stop gracefully shuts down the AuthorizationService by stopping its underlying
// service and closing worker channels.  Note that the connection provided to the
// service when created is not closed as it is not created by the service.
func (c *AuthorizationService) Stop() error {
	err := c.Service.Stop()
	if c.workersCh != nil {
		close(c.workersCh)
		c.wg.Wait()
	}
	return err
}

// decode processes the incoming micro.Request, verifying and decoding the payload,
// and ensuring its validity.
func (c *AuthorizationService) decode(
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

// sendResponse handles encoding, signing, encryption, and transmission of the
// authorization response to the client.  It processes both successful and error
// responses, encrypting the output if required, and sends it via msg.
func (c *AuthorizationService) sendResponse(
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

// AsyncWorkerHandler enqueues an incoming micro.Request to the workers channel for
// asynchronous processing.
func (c *AuthorizationService) AsyncWorkerHandler(msg micro.Request) {
	c.workersCh <- msg
}

// ServiceHandler processes incoming authorization micro.Request messages, decodes
// and validates them, and generates appropriate responses or errors based on the
// authorization outcome.
func (c *AuthorizationService) ServiceHandler(msg micro.Request) {
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
	// if we don't have a user nor an error - callout failed to do the right
	// thing, put an error
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
		// run some validation checks to help debugging service - these
		// don't stop the service just simply help getting an audit,
		// connection will fail on the server with Authorization Error
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

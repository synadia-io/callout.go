package callout

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/micro"
)

type Callout struct {
	authorizer Authorizer
	keys       *Keys
	logger     server.Logger
	errFn      AuthorizerErrCallback
	service    micro.Service
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
	if c.keys.EncryptionKey != nil && !isEncrypted {
		c.logger.Errorf("configuration mismatch: service requires encryption but server doesn't")
		return true, nil, fmt.Errorf("configuration mismatch: service requires encryption")
	}
	if c.keys.EncryptionKey == nil && isEncrypted {
		return true, nil, fmt.Errorf("configuration mismatch: service does not require encryption but server does")
	}

	var serverKey string
	if c.keys.EncryptionKey != nil {
		serverKey = msg.Headers().Get(NatsServerXKeyHeader)
		dd, err := c.keys.EncryptionKey.Open(data, serverKey)
		if err != nil {
			return true, nil, fmt.Errorf("failed to decrypt message: %v", err.Error())
		}
		data = dd
	}

	arc, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		return isEncrypted, nil, err
	}
	if arc.Audience != ExpectedAudience {
		return isEncrypted, nil, fmt.Errorf("unexpected audience")
	}

	return isEncrypted, &arc.AuthorizationRequest, nil
}

func (c *Callout) notify(err error) {
	c.logger.Errorf("%v", err)
	if c.errFn != nil {
		c.errFn(err)
	}
}

func (c *Callout) reject(msg micro.Request, err error) {
	c.notify(err)
	if err := msg.Error(
		"401",
		"reject",
		nil); err != nil {
		c.logger.Errorf("failed to respond: %v", err)
	}
}

func (c *Callout) sendResponse(msg micro.Request, isEncrypted bool, req *jwt.AuthorizationRequest, resp *jwt.AuthorizationResponseClaims) error {
	token, err := resp.Encode(c.keys.ResponseSigner)
	if err != nil {
		return fmt.Errorf("error encoding response for %s: %w", req.UserNkey, err)
	}
	data := []byte(token)
	if isEncrypted {
		data, err = c.keys.EncryptionKey.Seal([]byte(token), req.Server.XKey)
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
	// unpack
	isEncrypted, req, err := c.decode(msg)
	if err != nil {
		c.reject(msg, fmt.Errorf("failed to decode request %w", err))
		return
	}
	if req == nil {
		c.reject(msg, errors.New("failed to decode request: empty payload"))
		return
	}

	start := time.Now()
	defer func() {
		c.logger.Tracef("authorization for %s took %v", req.UserNkey, time.Since(start))
	}()

	// prepare the response
	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID
	if c.keys.ResponseSignerIssuer != nil {
		// key already validated
		resp.IssuerAccount, _ = c.keys.ResponseSignerIssuer.PublicKey()
	}
	// authorize
	user, err := c.authorizer(req)
	resp.Jwt = user
	// if we don't have a user nor an error - callout failed to do the right thing, put an error
	if user == "" && err == nil {
		err = fmt.Errorf("error authorizing %s: authorizer didn't generate a JWT", req.UserNkey)
	}
	// if we have an error, send the error
	if err != nil {
		resp.Error = err.Error()
	}

	if user != "" {
		// run some validation checks to help debugging service - these don't stop the service
		// just simply help getting an audit
		uc, err := jwt.DecodeUserClaims(user)
		if err != nil {
			c.notify(fmt.Errorf("authorizer generated invalid user for %s: %w", req.UserNkey, err))
		}
		if err == nil {
			vr := &jwt.ValidationResults{}
			uc.Validate(vr)
			errs := vr.Errors()
			if len(errs) > 0 {
				c.notify(fmt.Errorf("authorizer generated invalid user for %s: %w", req.UserNkey, errors.Join(errs...)))
			}
		}
	}

	if err := c.sendResponse(msg, isEncrypted, req, resp); err != nil {
		c.notify(err)
	}
}

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
	"strings"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// Name sets the name of the service. This value must not contain spaces or dots of
// it may be rejected by the micro.Service backing the AuthorizationService.
func Name(n string) Option {
	return func(o *Options) error {
		o.Name = n
		return nil
	}
}

// Authorizer sets a custom authorization function (AuthorizerFn) for signing
// and handling user JWTs in the service configuration.
func Authorizer(fn AuthorizerFn) Option {
	return func(o *Options) error {
		o.Authorizer = fn
		return nil
	}
}

// ErrCallback sets a callback function to handle errors returned by the
// AuthorizerFn, useful for logging or testing.
func ErrCallback(fn ErrCallbackFn) Option {
	return func(o *Options) error {
		o.ErrCallback = fn
		return nil
	}
}

// Logger sets the custom logger for the AuthorizationService.
func Logger(l natsserver.Logger) Option {
	return func(o *Options) error {
		o.Logger = l
		return nil
	}
}

// AsyncWorkers sets the number of asynchronous workers that will be used the AuthorizationService.
func AsyncWorkers(n int) Option {
	return func(o *Options) error {
		o.AsyncWorkers = n
		return nil
	}
}

// ResponseSignerKey sets the response signer key to be used for signing
// authorization responses in the authorization service. The key pair must be an
// account private key, otherwise an error is returned.
func ResponseSignerKey(kp nkeys.KeyPair) Option {
	return func(o *Options) error {
		seed, err := kp.Seed()
		if err != nil {
			return errors.Join(err, ErrBadCalloutOption)
		}
		if !bytes.HasPrefix(seed, []byte("SA")) {
			return errors.Join(
				errors.New("response signer key must be an account private key"),
				ErrBadCalloutOption,
			)
		}
		o.ResponseSignerKey = kp
		return nil
	}
}

// ResponseSigner sets a custom ResponseSignerFn to handle the signing of
// AuthorizationResponseClaims in the service options.
func ResponseSigner(fn ResponseSignerFn) Option {
	return func(o *Options) error {
		o.ResponseSigner = fn
		return nil
	}
}

// ServiceEndpoints configures the number of service endpoints for the
// AuthorizationService.
func ServiceEndpoints(n int) Option {
	return func(o *Options) error {
		o.ServiceEndpoints = n
		return nil
	}
}

// ResponseSignerIssuer configures the issuer for the response signer using an
// account public key or seed.  Returns an error if the provided key is invalid or
// not associated with an account.
func ResponseSignerIssuer(pub string) Option {
	return func(o *Options) error {
		if strings.HasPrefix(pub, "SA") {
			kp, err := nkeys.FromSeed([]byte(pub))
			if err != nil {
				return errors.Join(err, ErrBadCalloutOption)
			}
			pub, err = kp.PublicKey()
			if err != nil {
				return errors.Join(err, ErrBadCalloutOption)
			}
		} else if strings.HasPrefix(pub, "A") {
			_, err := nkeys.FromPublicKey(pub)
			if err != nil {
				return errors.Join(err, ErrBadCalloutOption)
			}
		} else {
			return errors.Join(errors.New("account public key required"), ErrBadCalloutOption)
		}
		o.ResponseSignerIssuer = pub
		return nil
	}
}

// InvalidUser configures a callback function invoked when a user JWT validation
// fails, passing the JWT and error details.
func InvalidUser(cb InvalidUserCallbackFn) Option {
	return func(o *Options) error {
		o.InvalidUser = cb
		return nil
	}
}

// EncryptionKey sets the encryption key for the service, requiring it to be a
// curve seed.  Returns an error for invalid keys.
func EncryptionKey(kp nkeys.KeyPair) Option {
	return func(o *Options) error {
		o.EncryptionKey = kp
		seed, err := kp.Seed()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(seed), "SX") {
			return errors.Join(
				errors.New("curve seed required"),
				ErrBadCalloutOption,
			)
		}
		return nil
	}
}

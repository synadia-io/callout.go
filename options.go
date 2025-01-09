package callout

import (
	"bytes"
	"errors"
	"strings"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func Name(n string) Option {
	return func(o *Options) error {
		o.Name = n
		return nil
	}
}

func Authorizer(fn AuthorizerFn) Option {
	return func(o *Options) error {
		o.Authorizer = fn
		return nil
	}
}

func ErrCallback(fn ErrCallbackFn) Option {
	return func(o *Options) error {
		o.ErrCallback = fn
		return nil
	}
}

func Logger(l natsserver.Logger) Option {
	return func(o *Options) error {
		o.Logger = l
		return nil
	}
}

func AsyncWorkers(n int) Option {
	return func(o *Options) error {
		o.AsyncWorkers = n
		return nil
	}
}

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

func ResponseSigner(fn ResponseSignerFn) Option {
	return func(o *Options) error {
		o.ResponseSigner = fn
		return nil
	}
}

func ServiceEndpoints(n int) Option {
	return func(o *Options) error {
		o.ServiceEndpoints = n
		return nil
	}
}

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

func InvalidUser(cb InvalidUserCallbackFn) Option {
	return func(o *Options) error {
		o.InvalidUser = cb
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
		if !strings.HasPrefix(string(seed), "SX") {
			return errors.Join(
				errors.New("curve seed required"),
				ErrBadCalloutOption,
			)
		}
		return nil
	}
}

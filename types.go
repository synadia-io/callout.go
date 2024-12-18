package callout

import (
	"bytes"
	"errors"
	"strings"

	"github.com/nats-io/nkeys"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

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

func ResponseSignerKey(kp nkeys.KeyPair) Option {
	return func(o *Options) error {
		seed, err := kp.Seed()
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(seed, []byte("SA")) {
			return errors.New("response signer key must be an account private key")
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

func InvalidUser(cb InvalidUserCallback) Option {
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
			return errors.New("curve seed required")
		}
		return nil
	}
}

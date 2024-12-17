package callout

import (
	"fmt"

	"github.com/nats-io/nkeys"
)

// FIXME: external signing will require a function instead
type Keys struct {
	ResponseSigner       nkeys.KeyPair
	ResponseSignerIssuer nkeys.KeyPair
	EncryptionKey        nkeys.KeyPair
}

func (k *Keys) CheckKey(kp nkeys.KeyPair, prefixByte nkeys.PrefixByte, seed bool) error {
	pub, _ := kp.PublicKey()
	if pre := nkeys.Prefix(pub); pre != prefixByte {
		return fmt.Errorf("expected %s, got %s", prefixByte, pre)
	}
	if seed {
		seed, _ := kp.Seed()
		if pre := nkeys.Prefix(string(seed)); pre != nkeys.PrefixByteSeed {
			return fmt.Errorf("expected %s, got %s", prefixByte, pre)
		}
	}
	return nil
}

func (k *Keys) Valid(hasIssuerFn bool) error {
	if !hasIssuerFn {
		if k.ResponseSigner == nil {
			return fmt.Errorf("ResponseSigner is required")
		}
		if err := k.CheckKey(k.ResponseSigner, nkeys.PrefixByteAccount, true); err != nil {
			return fmt.Errorf("ResponseSigner must be an account seed: %s", err.Error())
		}
		if k.ResponseSignerIssuer != nil {
			if err := k.CheckKey(k.ResponseSignerIssuer, nkeys.PrefixByteAccount, false); err != nil {
				return fmt.Errorf("ResponseSignerIssuer must be an account key: %s", err.Error())
			}
		}
	}
	if k.EncryptionKey != nil {
		if err := k.CheckKey(k.EncryptionKey, nkeys.PrefixByteCurve, true); err != nil {
			return fmt.Errorf("EncryptionKey must be a curve seed: %s", err.Error())
		}
	}
	return nil
}

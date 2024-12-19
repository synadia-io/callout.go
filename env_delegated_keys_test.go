package callout

import (
	"fmt"
	"testing"
	"time"

	authb "github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/nsc"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

// FIXME: need to handle keys manually
type DelegatedKeysEnv struct {
	t    *testing.T
	dir  *nst.TestDir
	auth authb.Auth

	userSigner          string
	authorizationSigner string

	sentinelCreds string
	serviceCreds  string
	keys          map[string]*authb.Key
}

func NewDelegatedKeysEnv(t *testing.T, dir *nst.TestDir) *DelegatedKeysEnv {
	// this uses the authb.Auth to build the entities
	// the option for KeysFn and sign enable to intercept the key creation
	// so that we have them - the test here will use actual keys to sign
	// the generated JWTs
	keys := make(map[string]*authb.Key)
	auth, err := authb.NewAuthWithOptions(
		nsc.NewNscProvider(
			fmt.Sprintf("%s/nsc/stores", dir),
			fmt.Sprintf("%s/nsc/keys", dir),
		), &authb.Options{
			KeysFn: func(p nkeys.PrefixByte) (*authb.Key, error) {
				kp, err := nkeys.CreatePair(p)
				if err != nil {
					return nil, err
				}
				key, err := authb.KeyFromNkey(kp, p)
				if err != nil {
					return nil, err
				}
				keys[key.Public] = key
				return key, nil
			},
			SignFn: func(pub string, data []byte) ([]byte, error) {
				k, ok := keys[pub]
				if !ok {
					return nil, fmt.Errorf("no key for %s", pub)
				}
				return k.Pair.Sign(data)
			},
		},
	)
	require.NoError(t, err)
	return &DelegatedKeysEnv{
		t:    t,
		dir:  dir,
		auth: auth,
		keys: keys,
	}
}

func (bc *DelegatedKeysEnv) GetServerConf() []byte {
	o, err := bc.auth.Operators().Add("O")
	require.NoError(bc.t, err)

	sys, err := o.Accounts().Add("SYS")
	require.NoError(bc.t, err)
	require.NoError(bc.t, o.SetSystemAccount(sys))

	// account where we place the users
	a, err := o.Accounts().Add("A")
	require.NoError(bc.t, err)
	// we are going to sign users with this key
	bc.userSigner, err = a.ScopedSigningKeys().Add()
	require.NoError(bc.t, err)

	// this is the auth callout account
	c, err := o.Accounts().Add("C")
	require.NoError(bc.t, err)
	// we are going to sign authorizations with this key
	bc.authorizationSigner, err = c.ScopedSigningKeys().Add()
	require.NoError(bc.t, err)

	cu, err := c.Users().Add("auth_user", "")
	require.NoError(bc.t, err)
	serviceCreds, err := cu.Creds(time.Hour)
	require.NoError(bc.t, err)
	bc.serviceCreds = bc.dir.WriteFile("service.creds", serviceCreds)

	// configure the external authorization
	require.NoError(bc.t,
		c.SetExternalAuthorizationUser([]authb.User{cu}, []authb.Account{a}, ""),
	)

	// sentinel credentials
	u, err := c.Users().Add("sentinel", "")
	require.NoError(bc.t, err)
	require.NoError(bc.t, u.PubPermissions().SetDeny(">"))
	require.NoError(bc.t, u.SubPermissions().SetDeny(">"))
	sentinelCreds, err := u.Creds(time.Hour)
	require.NoError(bc.t, err)
	bc.sentinelCreds = bc.dir.WriteFile("sentinel.creds", sentinelCreds)

	resolver := nst.ResolverFromAuth(bc.t, o)
	return resolver.Marshal(bc.t)
}

func (bc *DelegatedKeysEnv) GetAccount(name string) authb.Account {
	o, err := bc.auth.Operators().Get("O")
	require.NoError(bc.t, err)
	require.NotNil(bc.t, o)
	a, err := o.Accounts().Get(name)
	require.NoError(bc.t, err)
	require.NotNil(bc.t, a)
	return a
}

func (bc *DelegatedKeysEnv) EncodeUser(
	account string,
	claim jwt.Claims,
) (string, error) {
	a := bc.GetAccount(account)
	uc, ok := claim.(*jwt.UserClaims)
	require.True(bc.t, ok)
	// set the issuer
	uc.IssuerAccount = a.Subject()
	// look up the key we are supposed to use in the cache
	k, ok := bc.keys[bc.userSigner]
	if !ok {
		return "", fmt.Errorf("no key for %s", bc.userSigner)
	}
	// sign the user JWT
	return uc.Encode(k.Pair)
}

func (bc *DelegatedKeysEnv) ServiceUserOpts() []nats.Option {
	return []nats.Option{
		nats.UserCredentials(bc.serviceCreds),
	}
}

func (bc *DelegatedKeysEnv) UserOpts() []nats.Option {
	return []nats.Option{
		nats.UserCredentials(bc.sentinelCreds),
	}
}

func (bc *DelegatedKeysEnv) EncryptionKey() nkeys.KeyPair {
	return nil
}

func (bc *DelegatedKeysEnv) Audience() string {
	a := bc.GetAccount("A")
	return a.Subject()
}

func (bc *DelegatedKeysEnv) ServiceAudience() string {
	c := bc.GetAccount("C")
	return c.Subject()
}

func (bc *DelegatedKeysEnv) ServiceOpts() []Option {
	c := bc.GetAccount("C")
	skp, ok := bc.keys[bc.authorizationSigner]
	require.True(bc.t, ok)

	return []Option{ResponseSignerKey(skp.Pair), ResponseSignerIssuer(c.Subject())}
}

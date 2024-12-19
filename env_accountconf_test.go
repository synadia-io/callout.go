package callout

import (
	"testing"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

type BasicAccountEnv struct {
	t   *testing.T
	dir *nst.TestDir
	akp nkeys.KeyPair
}

func NewBasicAccountEnv(t *testing.T, dir *nst.TestDir) *BasicAccountEnv {
	akp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	return &BasicAccountEnv{
		t:   t,
		dir: dir,
		akp: akp,
	}
}

func (bc *BasicAccountEnv) GetServerConf() []byte {
	pk, err := bc.akp.PublicKey()
	require.NoError(bc.t, err)

	conf := &nst.Conf{Accounts: map[string]nst.Account{}}
	// the auth user is running in its own account
	conf.Accounts["AUTH"] = nst.Account{
		Users: []nst.User{
			{User: "auth", Password: "pwd"},
		},
	}
	conf.Authorization = nst.Authorization{AuthCallout: &nst.AuthCallout{}}
	conf.Authorization.AuthCallout.Issuer = pk
	conf.Authorization.AuthCallout.Account = "AUTH"
	conf.Authorization.AuthCallout.AuthUsers.Add("auth")

	// the account to place users in
	conf.Accounts["B"] = nst.Account{}
	return conf.Marshal(bc.t)
}

func (bc *BasicAccountEnv) EncodeUser(_ string, claim jwt.Claims) (string, error) {
	return claim.Encode(bc.akp)
}

func (bc *BasicAccountEnv) ServiceUserOpts() []nats.Option {
	return []nats.Option{nats.UserInfo("auth", "pwd")}
}

func (bc *BasicAccountEnv) UserOpts() []nats.Option {
	return []nats.Option{}
}

func (bc *BasicAccountEnv) EncryptionKey() nkeys.KeyPair {
	return nil
}

func (bc *BasicAccountEnv) Audience() string {
	return "B"
}

func (bc *BasicAccountEnv) ServiceAudience() string {
	return "AUTH"
}

func (bc *BasicAccountEnv) ServiceOpts() []Option {
	return []Option{
		ResponseSignerKey(bc.akp),
	}
}

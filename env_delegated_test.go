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

type DelegatedEnv struct {
	t           *testing.T
	dir         *nst.TestDir
	auth        authb.Auth
	aSigningKey string

	sentinelCreds string
	serviceCreds  string
	cSigningKey   string
}

func NewDelegatedEnv(t *testing.T, dir *nst.TestDir) *DelegatedEnv {
	// NscProvider shouldn't be used in production (should use the KvProvider) or
	// simply use Keys.
	auth, err := authb.NewAuth(
		nsc.NewNscProvider(
			fmt.Sprintf("%s/nsc/stores", dir),
			fmt.Sprintf("%s/nsc/keys", dir),
		),
	)
	require.NoError(t, err)
	return &DelegatedEnv{
		t:    t,
		dir:  dir,
		auth: auth,
	}
}

func (bc *DelegatedEnv) GetServerConf() []byte {
	o, err := bc.auth.Operators().Add("O")
	require.NoError(bc.t, err)

	sys, err := o.Accounts().Add("SYS")
	require.NoError(bc.t, err)
	require.NoError(bc.t, o.SetSystemAccount(sys))

	// account where we place the users
	a, err := o.Accounts().Add("A")
	require.NoError(bc.t, err)
	bc.aSigningKey, err = a.ScopedSigningKeys().Add()

	// this is the auth callout account
	c, err := o.Accounts().Add("C")
	require.NoError(bc.t, err)
	bc.cSigningKey, err = c.ScopedSigningKeys().Add()
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

func (bc *DelegatedEnv) GetAccount(name string) authb.Account {
	o, err := bc.auth.Operators().Get("O")
	require.NoError(bc.t, err)
	require.NotNil(bc.t, o)
	a, err := o.Accounts().Get(name)
	require.NoError(bc.t, err)
	require.NotNil(bc.t, a)
	return a
}

func (bc *DelegatedEnv) EncodeUser(
	account string,
	claim jwt.Claims,
) (string, error) {
	a := bc.GetAccount(account)
	uc, ok := claim.(*jwt.UserClaims)
	require.True(bc.t, ok)
	u, err := a.Users().ImportEphemeral(uc, bc.aSigningKey)
	require.NoError(bc.t, err)
	return u.JWT(), nil
}

func (bc *DelegatedEnv) ServiceUserOpts() []nats.Option {
	return []nats.Option{
		nats.UserCredentials(bc.serviceCreds),
	}
}

func (bc *DelegatedEnv) UserOpts() []nats.Option {
	return []nats.Option{
		nats.UserCredentials(bc.sentinelCreds),
	}
}

func (bc *DelegatedEnv) EncryptionKey() nkeys.KeyPair {
	return nil
}

func (bc *DelegatedEnv) Audience() string {
	a := bc.GetAccount("A")
	return a.Subject()
}

func (bc *DelegatedEnv) ServiceAudience() string {
	c := bc.GetAccount("C")
	return c.Subject()
}

func (bc *DelegatedEnv) ServiceOpts() []Option {
	c := bc.GetAccount("C")
	responseSignerFn := func(claims *jwt.AuthorizationResponseClaims) (string, error) {
		return c.IssueAuthorizationResponse(claims, bc.cSigningKey)
	}
	return []Option{ResponseSigner(responseSignerFn)}
}

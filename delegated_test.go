package callout

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	authb "github.com/synadia-io/jwt-auth-builder.go"
	"github.com/synadia-io/jwt-auth-builder.go/providers/nsc"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/suite"
)

func TestDelegated(t *testing.T) {
	suite.Run(t, new(DelegatedTestSuite))
}

type DelegatedTestSuite struct {
	suite.Suite
	dir           *nst.TestDir
	ns            *nst.NatsServer
	auth          authb.Auth
	aPub          string
	aSigningKey   string
	calloutKey    string
	sentinelCreds string
	serviceCreds  string
}

func (s *DelegatedTestSuite) SetupSuite() {
	s.dir = nst.NewTestDir(s.T(), "", "")

	var err error
	// NscProvider shouldn't be used in production (should use the KvProvider) or simply use Keys.
	s.auth, err = authb.NewAuth(nsc.NewNscProvider(fmt.Sprintf("%s/nsc/stores", s.dir), fmt.Sprintf("%s/nsc/keys", s.dir)))
	s.NoError(err)

	o, err := s.auth.Operators().Add("O")
	s.NoError(err)

	sys, err := o.Accounts().Add("SYS")
	s.NoError(err)
	s.NoError(o.SetSystemAccount(sys))

	// account where we place the users
	a, err := o.Accounts().Add("A")
	s.NoError(err)
	s.aPub = a.Subject()
	s.aSigningKey, err = a.ScopedSigningKeys().Add()

	// this is the auth callout account
	c, err := o.Accounts().Add("C")
	s.NoError(err)

	cu, err := c.Users().Add("auth_user", "")
	s.NoError(err)
	serviceCreds, err := cu.Creds(time.Hour)
	s.serviceCreds = s.dir.WriteFile("service.creds", serviceCreds)

	// configure the external authorization
	s.NoError(c.SetExternalAuthorizationUser([]authb.User{cu}, []authb.Account{a}, ""))

	// this is the sentinel user token, they can do nothing,
	sentinel, err := c.Users().Add("sentinel", "")
	s.NoError(err)
	s.NoError(sentinel.PubPermissions().SetDeny(">"))
	s.NoError(sentinel.SubPermissions().SetDeny(">"))
	// save the sentinel creds
	sentinelCreds, err := sentinel.Creds(time.Hour)
	s.NoError(err)
	s.sentinelCreds = s.dir.WriteFile("sentinels.creds", sentinelCreds)

	resolver := nst.ResolverFromAuth(s.T(), o)

	// start the server with the configuration
	s.ns = nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: s.dir.WriteFile("server.conf", resolver.Marshal(s.T())),
	})
}

func (s *DelegatedTestSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *DelegatedTestSuite) TestStart() {
	service, err := s.ns.MaybeConnect(nats.UserCredentials(s.serviceCreds))
	s.NoError(err)
	defer service.Close()

	// this will fail - service is not running yet
	_, err = s.ns.MaybeConnect(nats.UserCredentials(s.sentinelCreds), nats.MaxReconnects(1))
	s.Error(err)
	s.Contains(err.Error(), "timeout")

	o, _ := s.auth.Operators().Get("O")
	a, _ := o.Accounts().Get("A")
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		// Using auth builder to issue the JWT
		u, err := a.Users().AddWithIdentity("user", s.aSigningKey, req.UserNkey)
		s.NoError(err)
		err = u.PubPermissions().SetAllow("foo.bar", "$SYS.REQ.USER.INFO")
		s.NoError(err)
		err = u.SubPermissions().SetAllow("_INBOX.>")
		s.NoError(err)
		return u.JWT(), nil
	}

	// using a ResponseSignerFn to issue the AuthorizationResponse
	c, _ := o.Accounts().Get("C")
	responseSignerFn := func(claims *jwt.AuthorizationResponseClaims) (string, error) {
		return c.IssueAuthorizationResponse(claims, "")
	}

	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSigner(responseSignerFn))
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	nc, err := s.ns.MaybeConnect(nats.UserCredentials(s.sentinelCreds), nats.MaxReconnects(1))
	s.NoError(err)
	defer nc.Close()

	r, err := nc.Request("$SYS.REQ.USER.INFO", []byte{}, time.Second*2)
	s.NoError(err)

	var info nst.UserInfo
	s.NoError(json.Unmarshal(r.Data, &info))
	s.Equal(info.Data.Account, s.aPub)
	s.Len(info.Data.Permissions.Pub.Allow, 2)
	s.True(info.Data.Permissions.Pub.Allow.Contains("foo.bar"))
	s.True(info.Data.Permissions.Pub.Allow.Contains("$SYS.REQ.USER.INFO"))
	s.Len(info.Data.Permissions.Sub.Allow, 1)
	s.True(info.Data.Permissions.Sub.Allow.Contains("_INBOX.>"))
}

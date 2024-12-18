package callout

import (
	"fmt"
	"testing"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/suite"
)

func TestAccConf(t *testing.T) {
	suite.Run(t, new(ConfAccTestSuite))
}

type ConfAccTestSuite struct {
	suite.Suite
	// Key for authorization response
	akp nkeys.KeyPair
	dir *nst.TestDir
	ns  *nst.NatsServer
}

func (s *ConfAccTestSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *ConfAccTestSuite) SetupSuite() {
	s.dir = nst.NewTestDir(s.T(), "", "")

	// Generate the key for the issuer. Callouts for conf setups are slightly different
	// because the authorization function will sign the user using the issuer, which also
	// signs the authorizer response
	s.akp, _ = nkeys.FromSeed([]byte("SAAHD5MPQZ6VJVUJUBEGD75GKFTARXNOAFDFJE3G7XZKN3H5V2Y4QPSH54"))
	pk, _ := s.akp.PublicKey()

	// this is an example of a NATS server configuration that uses the authorizer to place
	// users into account B. The server expects the authorization to be signed by the
	// specific account nkey. Note that this is using a conf accounts, not delegated,
	// so there are no account JWTs.
	// The authorization section contains  `auth` user which will be used by the callout
	// service to connect
	conf := nst.Conf{Accounts: map[string]nst.Account{}}

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

	configFile := s.dir.WriteFile("server.conf", conf.Marshal(s.T()))

	// start the server with the configuration
	s.ns = nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: configFile,
		Debug:      true,
		Trace:      true,
		NoLog:      false,
	})
}

func (s *ConfAccTestSuite) connectService() *nats.Conn {
	nc, err := s.ns.MaybeConnect(nats.UserInfo("auth", "pwd"))
	s.NoError(err)
	s.NotNil(nc)
	return nc
}

func (s *ConfAccTestSuite) TestOK() {
	// here's a simple Authorizer function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "B"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		return uc.Encode(s.akp)
	}

	service := s.connectService()
	defer service.Close()
	info := nst.ClientInfo(s.T(), service)
	s.Equal("AUTH", info.Data.Account)

	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	nc2, err := s.ns.MaybeConnect(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc2)

	info = nst.ClientInfo(s.T(), nc2)
	s.Contains(info.Data.Permissions.Pub.Allow, nst.UserInfoSubj)
	s.Contains(info.Data.Permissions.Sub.Allow, "_INBOX.>")
}

func (s *ConfAccTestSuite) TestBadAccount() {
	// here's a simple Authorizer function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "X"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		return uc.Encode(s.akp)
	}

	service := s.connectService()
	defer service.Close()
	info := nst.ClientInfo(s.T(), service)
	s.Equal("AUTH", info.Data.Account)

	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	_, err = s.ns.MaybeConnect(nats.UserInfo("x", "y"))
	s.Error(err)
	s.Contains(err.Error(), "Authorization Violation")
}

func (s *ConfAccTestSuite) TestBlackListed() {
	// here's a simple Authorizer function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		if req.ConnectOptions.Username == "blacklisted" {
			return "", fmt.Errorf("bad guy")
		}
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "B"
		return uc.Encode(s.akp)
	}

	service := s.connectService()
	defer service.Close()

	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()
	nc1, err := s.ns.MaybeConnect(nats.UserInfo("a", "b"))
	s.NoError(err)
	s.NotNil(nc1)

	nc2, err := s.ns.MaybeConnect(nats.UserInfo("blacklisted", "secret"), nats.MaxReconnects(1))
	s.Error(err)
	s.Nil(nc2)
}

func (s *ConfAccTestSuite) TestBadGenerate() {
	// here's a simple Authorizer function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		if req.ConnectOptions.Username == "bad generate" {
			// this is generating a wrong JWT (account instead of user)
			kp, err := nkeys.CreateAccount()
			s.NoError(err)
			id, err := kp.PublicKey()
			s.NoError(err)
			uc := jwt.NewAccountClaims(id)
			return uc.Encode(s.akp)
		}
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "B"
		return uc.Encode(s.akp)
	}

	service := s.connectService()
	defer service.Close()

	var lastErr error
	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSignerKey(s.akp), InvalidUser(func(_ string, err error) {
		lastErr = err
	}))
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	nc1, err := s.ns.MaybeConnect(nats.UserInfo("a", "b"))
	s.NoError(err)
	s.NotNil(nc1)

	nc2, err := s.ns.MaybeConnect(nats.UserInfo("bad generate", "secret"), nats.MaxReconnects(1))
	s.Error(err)
	s.Nil(nc2)
	s.Error(lastErr)
	s.Contains(lastErr.Error(), "not user claim")
}

func (s *ConfAccTestSuite) TestBadPermissions() {
	// here's a simple Authorizer function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		if req.ConnectOptions.Username == "bad perms" {
			uc := jwt.NewUserClaims(req.UserNkey)
			// bad subject
			uc.Pub.Allow.Add(".hello.")
			return uc.Encode(s.akp)
		}
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "B"
		return uc.Encode(s.akp)
	}

	service := s.connectService()
	defer service.Close()

	var lastErr error
	svc, err := AuthorizationService(service, AuthorizerFn(authorizer), ResponseSignerKey(s.akp), InvalidUser(func(_ string, err error) {
		lastErr = err
	}))
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	nc1, err := s.ns.MaybeConnect(nats.UserInfo("a", "b"))
	s.NoError(err)
	s.NotNil(nc1)

	nc2, err := s.ns.MaybeConnect(nats.UserInfo("bad perms", "secret"), nats.MaxReconnects(1))
	s.Error(err)
	s.Nil(nc2)
	s.Error(lastErr)
	s.Contains(lastErr.Error(), "cannot start or end with a `.`")
}

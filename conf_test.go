package callout

import (
	"fmt"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/suite"
)

func TestConf(t *testing.T) {
	suite.Run(t, new(ConfTestSuite))
}

type ConfTestSuite struct {
	suite.Suite
	// Key for authorization response
	akp nkeys.KeyPair
	dir *nst.TestDir
	ns  *nst.NatsServer
}

func (s *ConfTestSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *ConfTestSuite) SetupSuite() {
	s.dir = nst.NewTestDir(s.T(), "", "")

	// Generate the key for the issuer. Callouts for conf setups are slightly different
	// because the authorization function will sign the user using the issuer, which also
	// signs the authorizer response
	s.akp, _ = nkeys.CreateAccount()
	pk, _ := s.akp.PublicKey()

	// this is an example of a NATS server configuration that uses the authorizer to place
	// users into account B. The server expects the authorization to be signed by the
	// specific account nkey. Note that this is using a conf accounts, not delegated,
	// so there are no account JWTs.
	// The authorization section contains  `auth` user which will be used by the callout
	// service to connect
	sys := "SYS"
	conf := nst.Conf{Accounts: map[string]nst.Account{}}
	conf.SystemAccount = &sys
	// the account to place users in
	conf.Accounts["B"] = nst.Account{}
	conf.Accounts["SYS"] = nst.Account{}
	// the auth user is in $G
	conf.Authorization = nst.Authorization{AuthCallout: &nst.AuthCallout{}}
	conf.Authorization.Users.Add(nst.User{User: "auth", Password: "pwd"})
	conf.Authorization.AuthCallout.Issuer = pk
	conf.Authorization.AuthCallout.AuthUsers.Add("auth")

	configFile := s.dir.WriteFile("server.conf", conf.Marshal(s.T()))

	// start the server with the configuration
	s.ns = nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: configFile,
		Debug:      true,
		Trace:      true,
		NoLog:      false,
	})
}

func (s *ConfTestSuite) connectService() *nats.Conn {
	nc, err := s.ns.MaybeConnect(nats.UserInfo("auth", "pwd"))
	s.NoError(err)
	s.NotNil(nc)
	s.T().Logf("Connected to service: %s", nc.ConnectedUrl())
	return nc
}

func (s *ConfTestSuite) TestEncryptionNotRequired() {
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		s.Fail("shouldn't have been called")
		return "", nil
	}
	service := s.connectService()
	defer service.Close()
	info := nst.ClientInfo(s.T(), service)
	s.Equal("$G", info.Data.Account)

	kp, _ := nkeys.CreateCurveKeys()
	svc, err := AuthorizationService(service,
		AuthorizerFn(authorizer),
		ResponseSignerKey(s.akp),
		EncryptionKey(kp),
	)
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	_, err = s.ns.MaybeConnect(nats.UserInfo("hello", "world"))
	s.Error(err)
}

func (s *ConfTestSuite) TestCannotPubOnSysReqUserAuth() {
	service := s.connectService()
	defer service.Close()

	svc, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			if req.ConnectOptions.Username == "spoof" {
				uc := jwt.NewUserClaims(req.UserNkey)
				uc.Audience = "$G"
				uc.Pub.Allow.Add("$SYS.>")
				return uc.Encode(s.akp)
			}
			uc := jwt.NewUserClaims(req.UserNkey)
			uc.Audience = "B"
			return uc.Encode(s.akp)
		}),
		ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer func() { _ = svc.Stop() }()

	info := nst.ClientInfo(s.T(), service)
	s.Equal("$G", info.Data.Account)

	var lastErr error
	nc1, err := s.ns.MaybeConnect(nats.UserInfo("spoof", "nothing"), nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
		lastErr = err
	}))
	s.NoError(err)
	defer nc1.Close()
	info = nst.ClientInfo(s.T(), nc1)
	s.Equal("$G", info.Data.Account)
	s.Contains(info.Data.Permissions.Pub.Allow, "$SYS.>")

	// send no payload
	_, err = nc1.Request(SysRequestUserAuthSubj, nil, 1*time.Second)
	s.Error(err)
	s.Contains(err.Error(), "timeout")
	s.Error(lastErr)
	s.Contains(lastErr.Error(), "Permissions Violation for Publish to \"$SYS.REQ.USER.AUTH\"")
}

func (s *ConfTestSuite) TestCannotPubOnSys() {
	service := s.connectService()
	defer service.Close()

	svc, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			if req.ConnectOptions.Username == "sys" {
				uc := jwt.NewUserClaims(req.UserNkey)
				uc.Audience = "SYS"
				uc.Pub.Allow.Add(">")
				return uc.Encode(s.akp)
			}
			uc := jwt.NewUserClaims(req.UserNkey)
			uc.Audience = "B"
			return uc.Encode(s.akp)
		}),
		ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer func() { _ = svc.Stop() }()

	info := nst.ClientInfo(s.T(), service)
	s.Equal("$G", info.Data.Account)

	nc1, err := s.ns.MaybeConnect(nats.UserInfo("sys", "nothing"))
	s.NoError(err)
	defer nc1.Close()
	info = nst.ClientInfo(s.T(), nc1)
	s.Equal("SYS", info.Data.Account)
	s.Contains(info.Data.Permissions.Pub.Allow, ">")

	// send no payload
	_, err = nc1.Request(SysRequestUserAuthSubj, nil, 1*time.Second)
	s.Error(err)
	s.Contains(err.Error(), "no responders")
}

func (s *ConfTestSuite) TestAuthorizerFnIsRequired() {
	service := s.connectService()
	defer service.Close()

	_, err := AuthorizationService(service,
		ResponseSignerKey(s.akp))
	s.Error(err)
	s.Contains(err.Error(), "authorizer is required")
}

func (s *ConfTestSuite) TestSignerOrKeys() {
	service := s.connectService()
	defer service.Close()

	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSigner(func(req *jwt.AuthorizationResponseClaims) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(s.akp))
	s.Error(err)
	s.Contains(err.Error(), "response signer key/issuer are mutually exclusive")
}

func (s *ConfTestSuite) TestResponseSignerKeyMustBeSeed() {
	service := s.connectService()
	defer service.Close()

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()
	pub, _ := nkeys.FromPublicKey(pk)
	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(pub))
	s.Error(err)
	s.Contains(err.Error(), "no seed or private key available")
}

func (s *ConfTestSuite) TestResponseSignerKeyMustBeAccount() {
	service := s.connectService()
	defer service.Close()

	kp, _ := nkeys.CreateUser()
	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(kp))
	s.Error(err)
	s.Contains(err.Error(), "must be an account private key")
}

func (s *ConfTestSuite) TestResponseSignerIssuerMustBeAccount() {
	service := s.connectService()
	defer service.Close()

	kp, _ := nkeys.CreateUser()
	pk, _ := kp.PublicKey()
	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerIssuer(pk))
	s.Error(err)
	s.Contains(err.Error(), "account public key required")
}

func (s *ConfTestSuite) TestResponseSignerIssuerCouldBeSeed() {
	service := s.connectService()
	defer service.Close()

	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerIssuer(string(seed)))
	s.NoError(err)
}

func (s *ConfTestSuite) TestEncryptKey() {
	service := s.connectService()
	defer service.Close()

	kp, _ := nkeys.CreateAccount()
	_, err := AuthorizationService(service,
		AuthorizerFn(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		EncryptionKey(kp))
	s.Error(err)
	s.Contains(err.Error(), "curve seed required")
}

func (s *ConfTestSuite) TestOK() {
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

	svc, err := AuthorizationService(service,
		AuthorizerFn(authorizer),
		ResponseSignerKey(s.akp))
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	nc2, err := s.ns.MaybeConnect(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc2)

	info := nst.ClientInfo(s.T(), nc2)
	s.Contains(info.Data.Permissions.Pub.Allow, nst.UserInfoSubj)
	s.Contains(info.Data.Permissions.Sub.Allow, "_INBOX.>")
}

func (s *ConfTestSuite) TestBlackListed() {
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

func (s *ConfTestSuite) TestBadGenerate() {
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
	svc, err := AuthorizationService(service,
		AuthorizerFn(authorizer),
		ResponseSignerKey(s.akp),
		InvalidUser(func(_ string, err error) {
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

func (s *ConfTestSuite) TestBadPermissions() {
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
	svc, err := AuthorizationService(service,
		AuthorizerFn(authorizer),
		ResponseSignerKey(s.akp),
		InvalidUser(func(_ string, err error) {
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

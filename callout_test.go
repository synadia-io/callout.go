package callout

import (
	"errors"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/suite"
)

type CalloutSuite struct {
	suite.Suite
	dir *nst.TestDir
	env CalloutEnv
	ns  *nst.NatsServer
}

func NewCalloutSuite(t *testing.T) *CalloutSuite {
	return &CalloutSuite{dir: nst.NewTestDir(t, "", "")}
}

type CalloutEnv interface {
	// GetConf returns the server configuration
	GetServerConf() []byte
	// ServiceConnOpts returns additional service connection options
	ServiceUserOpts() []nats.Option
	ServiceAudience() string
	EncryptionKey() nkeys.KeyPair
	Audience() string
	EncodeUser(account string, claim jwt.Claims) (string, error)
	ServiceOpts() []Option
	UserOpts() []nats.Option
}

func TestBasicEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestBasicAccountEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicAccountEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestBasicEncryptedEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicEncryptedEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestDelegatedEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewDelegatedEnv(t, cs.dir)
	suite.Run(t, cs)
}

//func TestDelegatedKeysEnv(t *testing.T) {
//	cs := NewCalloutSuite(t)
//	cs.env = NewDelegatedKeysEnv(t, cs.dir)
//	suite.Run(t, cs)
//}

func (s *CalloutSuite) SetupServer(conf []byte) *nst.NatsServer {
	return nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: s.dir.WriteFile("server.conf", conf),
		Port:       -1,
		Debug:      true,
		Trace:      true,
		NoLog:      false,
	})
}

func (s *CalloutSuite) SetupSuite() {
	s.ns = s.SetupServer(s.env.GetServerConf())
}

func (s *CalloutSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *CalloutSuite) getServiceConn() *nats.Conn {
	nc, err := s.ns.MaybeConnect(s.env.ServiceUserOpts()...)
	s.NoError(err)
	return nc
}

func (s *CalloutSuite) userConn(opts ...nats.Option) (*nats.Conn, error) {
	buf := append(opts, s.env.UserOpts()...)
	return s.ns.MaybeConnect(buf...)
}

func (s *CalloutSuite) TestEncryptionMismatch() {
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		s.Fail("shouldn't have been called")
		return "", nil
	}
	service := s.getServiceConn()
	defer service.Close()
	info := nst.ClientInfo(s.T(), service)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	// require AuthorizeFn min
	var lastErr error
	kp, _ := nkeys.CreateCurveKeys()
	opts := []Option{
		Authorizer(authorizer),
		ErrCallback(func(err error) {
			lastErr = err
		}),
	}
	// want to fail on mismatch
	// if not required add it otherwise don't
	if s.env.EncryptionKey() == nil {
		opts = append(opts, EncryptionKey(kp))
	}
	svc, err := AuthorizationService(service, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	_, err = s.userConn(nats.MaxReconnects(1))
	s.Error(err)
	s.Contains(err.Error(), "timeout")

	s.Error(lastErr)
	s.Contains(lastErr.Error(), "encryption mismatch")
}

func (s *CalloutSuite) TestAuthorizerIsRequired() {
	service := s.getServiceConn()
	defer service.Close()

	_, err := AuthorizationService(service,
		ResponseSigner(func(req *jwt.AuthorizationResponseClaims) (string, error) {
			return "", nil
		}))
	s.Error(err)
	s.True(errors.Is(err, ErrAuthorizerRequired))
}

func (s *CalloutSuite) TestSignerOrKeys() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSigner(func(req *jwt.AuthorizationResponseClaims) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp))
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerMustBeSeed() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()
	pk, _ := akp.PublicKey()
	pub, _ := nkeys.FromPublicKey(pk)

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(pub))
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerMustBeAccount() {
	service := s.getServiceConn()
	defer service.Close()
	ukp, _ := nkeys.CreateUser()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(ukp))
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) RestResponseSignerIssuerMustBeAccount() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	ukp, _ := nkeys.CreateUser()
	pk, _ := ukp.PublicKey()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(pk))
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerIssuerCouldBeSeed() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	sk, _ := nkeys.CreateAccount()
	sks, _ := sk.Seed()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(string(sks)))
	s.NoError(err)
}

func (s *CalloutSuite) TestResponseSignerIssuer() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	sk, _ := nkeys.CreateAccount()
	pk, _ := sk.PublicKey()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(pk))
	s.NoError(err)
}

func (s *CalloutSuite) TestResponseSignerIssuerBadType() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()
	ukp, _ := nkeys.CreateUser()
	upk, _ := ukp.PublicKey()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(upk))
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestEncryptKey() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		EncryptionKey(akp),
	)
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestEncryptKeyMustBeSeed() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateCurveKeys()
	pk, _ := akp.PublicKey()
	pub, _ := nkeys.FromPublicKey(pk)

	_, err := AuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		EncryptionKey(pub),
	)
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestSetupOK() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = s.env.Audience()
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		return s.env.EncodeUser("A", uc)
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	opts := append(s.env.ServiceOpts(), Authorizer(authorizer))
	svc, err := AuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	c, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(c)
	info = nst.ClientInfo(s.T(), c)
	s.Contains(info.Data.Permissions.Pub.Allow, nst.UserInfoSubj)
	s.Contains(info.Data.Permissions.Sub.Allow, "_INBOX.>")
}

func (s *CalloutSuite) TestAbortRequest() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		if req.ConnectOptions.Username == "blacklisted" {
			return "", ErrAbortRequest
		}
		if req.ConnectOptions.Username == "errorme" {
			return "", errors.New("service error: testing errorme")
		}
		if req.ConnectOptions.Username == "blank" {
			return "", nil
		}
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = s.env.Audience()
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90_000
		return s.env.EncodeUser("A", uc)
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	opts := append(s.env.ServiceOpts(), Authorizer(authorizer))
	svc, err := AuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	nc, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc)
	defer nc.Close()

	_, err = s.userConn(
		nats.UserInfo("errorme", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
	s.Contains(err.Error(), "Authorization Violation")

	_, err = s.userConn(
		nats.UserInfo("blacklisted", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
	s.Contains(err.Error(), "timeout")

	_, err = s.userConn(
		nats.UserInfo("blank", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
	s.Contains(err.Error(), "timeout")
}

func (s *CalloutSuite) TestBadGenerate() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		if req.ConnectOptions.Username == "bad generate" {
			// this is generating a wrong JWT (account instead of user)
			kp, err := nkeys.CreateAccount()
			s.NoError(err)
			id, err := kp.PublicKey()
			s.NoError(err)
			ac := jwt.NewAccountClaims(id)
			return ac.Encode(kp)
		}
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = s.env.Audience()
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90_000
		return s.env.EncodeUser("A", uc)
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	var lastErr error
	opts := append(
		s.env.ServiceOpts(),
		Authorizer(authorizer),
		InvalidUser(func(_ string, err error) {
			lastErr = err
		}),
	)
	svc, err := AuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	nc, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc)
	defer nc.Close()

	_, err = s.userConn(
		nats.UserInfo("bad generate", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
	s.Contains(err.Error(), "Authorization Violation")

	s.Error(lastErr)
	s.Contains(lastErr.Error(), "not user claim")
}

func (s *CalloutSuite) TestBadPermissions() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = s.env.Audience()
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90_000

		if req.ConnectOptions.Username == "bad perms" {
			uc.Pub.Allow.Add(".bad.")
		}
		return s.env.EncodeUser("A", uc)
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	var lastErr error
	opts := append(
		s.env.ServiceOpts(),
		Authorizer(authorizer),
		InvalidUser(func(_ string, err error) {
			lastErr = err
		}),
	)
	svc, err := AuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	nc, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc)
	defer nc.Close()

	_, err = s.userConn(
		nats.UserInfo("bad perms", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
	s.Contains(err.Error(), "Authorization Violation")

	s.Error(lastErr)
	s.Contains(lastErr.Error(), "cannot start or end with a `.`")
}

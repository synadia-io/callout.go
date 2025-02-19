package callout

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/suite"
)

type CalloutSuite struct {
	suite.Suite
	dir *nst.TestDir
	env CalloutEnv
	ns  nst.NatsServer
}

func NewCalloutSuite(t *testing.T) *CalloutSuite {
	return &CalloutSuite{dir: nst.NewTestDir(t, os.TempDir(), "callout_test")}
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

func TestDelegatedKeysEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewDelegatedKeysEnv(t, cs.dir)
	suite.Run(t, cs)
}

func (s *CalloutSuite) SetupServer(conf []byte) nst.NatsServer {
	return nst.NewNatsServer(s.dir, &nst.Options{
		ConfigFile: s.dir.WriteFile("server.conf", conf),
		Port:       -1,
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
		Logger(nst.NewNilLogger()),
	}
	// want to fail on mismatch
	// if not required add it otherwise don't
	if s.env.EncryptionKey() == nil {
		opts = append(opts, EncryptionKey(kp))
	}
	svc, err := NewAuthorizationService(service, opts...)
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

	_, err := NewAuthorizationService(service,
		ResponseSigner(func(req *jwt.AuthorizationResponseClaims) (string, error) {
			return "", nil
		}),
		Logger(nst.NewNilLogger()))
	s.Error(err)
	s.True(errors.Is(err, ErrAuthorizerRequired))
}

func (s *CalloutSuite) TestSignerOrKeys() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSigner(func(req *jwt.AuthorizationResponseClaims) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp))
	Logger(nst.NewNilLogger())
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerMustBeSeed() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()
	pk, _ := akp.PublicKey()
	pub, _ := nkeys.FromPublicKey(pk)

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(pub),
		Logger(nst.NewNilLogger()))

	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerMustBeAccount() {
	service := s.getServiceConn()
	defer service.Close()
	ukp, _ := nkeys.CreateUser()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(ukp),
		Logger(nst.NewNilLogger()))

	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) RestResponseSignerIssuerMustBeAccount() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	ukp, _ := nkeys.CreateUser()
	pk, _ := ukp.PublicKey()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(pk),
		Logger(nst.NewNilLogger()))
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestResponseSignerIssuerCouldBeSeed() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	sk, _ := nkeys.CreateAccount()
	sks, _ := sk.Seed()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(string(sks)),
		Logger(nst.NewNilLogger()))
	s.NoError(err)
}

func (s *CalloutSuite) TestResponseSignerIssuer() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	sk, _ := nkeys.CreateAccount()
	pk, _ := sk.PublicKey()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(pk),
		Logger(nst.NewNilLogger()))
	s.NoError(err)
}

func (s *CalloutSuite) TestResponseSignerIssuerBadType() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()
	ukp, _ := nkeys.CreateUser()
	upk, _ := ukp.PublicKey()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		ResponseSignerIssuer(upk),
		Logger(nst.NewNilLogger()))
	s.Error(err)
	s.True(errors.Is(err, ErrBadCalloutOption))
}

func (s *CalloutSuite) TestEncryptKey() {
	service := s.getServiceConn()
	defer service.Close()
	akp, _ := nkeys.CreateAccount()

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		EncryptionKey(akp),
		Logger(nst.NewNilLogger()),
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

	_, err := NewAuthorizationService(service,
		Authorizer(func(req *jwt.AuthorizationRequest) (string, error) {
			return "", nil
		}),
		ResponseSignerKey(akp),
		EncryptionKey(pub),
		Logger(nst.NewNilLogger()),
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

	opts := append(s.env.ServiceOpts(), Authorizer(authorizer), Logger(nst.NewNilLogger()))
	svc, err := NewAuthorizationService(serviceConn, opts...)
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

	opts := append(s.env.ServiceOpts(), Authorizer(authorizer), Logger(nst.NewNilLogger()))
	svc, err := NewAuthorizationService(serviceConn, opts...)
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
		Logger(nst.NewNilLogger()),
	)
	svc, err := NewAuthorizationService(serviceConn, opts...)
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
		Logger(nst.NewNilLogger()),
	)
	svc, err := NewAuthorizationService(serviceConn, opts...)
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

func (s *CalloutSuite) TestBadEncryption() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		return "", errors.New("not allowed")
	}

	var lastErr error
	opts := append(
		s.env.ServiceOpts(),
		Authorizer(authorizer),
		ErrCallback(func(err error) {
			lastErr = err
		}),
		Logger(nst.NewNilLogger()),
	)

	options, err := processOptions(opts...)
	s.NoError(err)
	options.Logger = nslogger.NewStdLogger(true, true, true, true, true)
	options.Authorizer = authorizer
	callout := &AuthorizationService{opts: options}

	handler := callout.ServiceHandler
	// empty payload
	handler(NewServiceMsgAdapter(&nats.Msg{}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: empty payload"))

	// not enough characters
	handler(NewServiceMsgAdapter(&nats.Msg{Data: []byte("123")}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: payload too short: 3"))

	// encryption error
	handler(NewServiceMsgAdapter(&nats.Msg{Data: []byte("this is not valid")}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: error decrypting message"))

	// encryption error
	handler(NewServiceMsgAdapter(&nats.Msg{Data: []byte("eyJ0junk")}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: error decoding auth request"))

	akp, err := nkeys.CreateAccount()
	s.NoError(err)
	aid, err := akp.PublicKey()
	s.NoError(err)
	ukp, err := nkeys.CreateUser()
	s.NoError(err)
	id, err := ukp.PublicKey()
	s.NoError(err)
	skp, err := nkeys.CreateServer()
	s.NoError(err)
	sid, err := skp.PublicKey()
	s.NoError(err)

	// different issuer
	skp2, err := nkeys.CreateServer()
	s.NoError(err)
	sid2, err := skp2.PublicKey()
	s.NoError(err)

	rc := jwt.NewAuthorizationRequestClaims(aid)
	rc.Audience = ExpectedAudience
	rc.UserNkey = id
	rc.Server = jwt.ServerID{ID: sid2}
	token, err := rc.Encode(skp)
	s.NoError(err)
	handler(NewServiceMsgAdapter(&nats.Msg{Data: []byte(token)}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: issuers don't match"))

	// bad audience
	rc = jwt.NewAuthorizationRequestClaims(aid)
	rc.Audience = "Different Audience"
	rc.UserNkey = id
	rc.Server = jwt.ServerID{ID: sid}
	token, err = rc.Encode(skp)
	s.NoError(err)
	handler(NewServiceMsgAdapter(&nats.Msg{Data: []byte(token)}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: unexpected audience"))
}

func (s *CalloutSuite) TestAsyncWorkers() {
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

	opts := append(s.env.ServiceOpts(),
		Authorizer(authorizer),
		Logger(nst.NewNilLogger()),
		AsyncWorkers(5))
	svc, err := NewAuthorizationService(serviceConn, opts...)
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

func (s *CalloutSuite) TestErrorHandler() {
	// here's a simple AuthorizerFn function that authorizes all users
	theErr := errors.New("testing")
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		return "", theErr
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	var lastErr error
	errCb := func(err error) {
		lastErr = err
	}

	opts := append(s.env.ServiceOpts(),
		Authorizer(authorizer),
		// Logger(nst.NewNilLogger()),
		ErrCallback(errCb))
	svc, err := NewAuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	c, err := s.userConn(nats.UserInfo("hello", "world"))
	s.Error(err)
	s.Nil(c)

	s.Error(lastErr)
	s.True(errors.Is(lastErr, theErr))
}

func (s *CalloutSuite) TestUserErrorHandler() {
	// here's a simple AuthorizerFn function that authorizes all users
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		return "not a jwt", nil
	}

	serviceConn := s.getServiceConn()
	defer serviceConn.Close()
	info := nst.ClientInfo(s.T(), serviceConn)
	s.Equal(s.env.ServiceAudience(), info.Data.Account)

	var jwtErr error
	var token string
	iuCb := func(jwt string, err error) {
		token = jwt
		jwtErr = err
	}

	opts := append(s.env.ServiceOpts(),
		Authorizer(authorizer),
		Logger(nst.NewNilLogger()),
		InvalidUser(iuCb))
	svc, err := NewAuthorizationService(serviceConn, opts...)
	s.NoError(err)
	s.NotNil(svc)
	defer func() {
		_ = svc.Stop()
	}()

	c, err := s.userConn(nats.UserInfo("hello", "world"))
	s.Error(err)
	s.Nil(c)

	s.Error(jwtErr)
	s.Equal(token, "not a jwt")
}

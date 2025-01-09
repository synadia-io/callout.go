package callout

import (
	"errors"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	nslogger "github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
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

func TestDelegatedKeysEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewDelegatedKeysEnv(t, cs.dir)
	suite.Run(t, cs)
}

func (s *CalloutSuite) SetupServer(conf []byte) *nst.NatsServer {
	return nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: s.dir.WriteFile("server.conf", conf),
		Port:       -1,
		Debug:      false,
		Trace:      false,
		NoLog:      true,
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
		}),
		Logger(nst.NewNilLogger()))
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	_, err := AuthorizationService(service,
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

	opts := append(s.env.ServiceOpts(), Authorizer(authorizer), Logger(nst.NewNilLogger()))
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
		Logger(nst.NewNilLogger()),
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
		Logger(nst.NewNilLogger()),
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
	callout := &Callout{opts: options}

	handler := callout.ServiceHandler
	// empty payload
	handler(AdaptMsg(&nats.Msg{}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: empty payload"))

	// not enough characters
	handler(AdaptMsg(&nats.Msg{Data: []byte("123")}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: payload too short: 3"))

	// encryption error
	handler(AdaptMsg(&nats.Msg{Data: []byte("this is not valid")}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: error decrypting message"))

	// encryption error
	handler(AdaptMsg(&nats.Msg{Data: []byte("eyJ0junk")}))
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
	handler(AdaptMsg(&nats.Msg{Data: []byte(token)}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: issuers don't match"))

	// bad audience
	rc = jwt.NewAuthorizationRequestClaims(aid)
	rc.Audience = "Different Audience"
	rc.UserNkey = id
	rc.Server = jwt.ServerID{ID: sid}
	token, err = rc.Encode(skp)
	s.NoError(err)
	handler(AdaptMsg(&nats.Msg{Data: []byte(token)}))
	s.Error(lastErr)
	errors.Is(lastErr, errors.New("bad request: unexpected audience"))
}

type ServiceMsgAdapter struct {
	msg *nats.Msg
}

func AdaptMsg(m *nats.Msg) *ServiceMsgAdapter {
	return &ServiceMsgAdapter{m}
}

func (m *ServiceMsgAdapter) Respond([]byte, ...micro.RespondOpt) error {
	return m.msg.Respond(m.msg.Data)
}

func (m *ServiceMsgAdapter) RespondJSON(any, ...micro.RespondOpt) error {
	return m.msg.Respond(m.msg.Data)
}

func (m *ServiceMsgAdapter) Error(code, description string, data []byte, opts ...micro.RespondOpt) error {
	return nil
}

// Data returns request data.
func (m *ServiceMsgAdapter) Data() []byte {
	return m.msg.Data
}

// Headers returns request headers.
func (m *ServiceMsgAdapter) Headers() micro.Headers {
	return nil
}

// Subject returns underlying NATS message subject.
func (m *ServiceMsgAdapter) Subject() string {
	return m.msg.Subject
}

func (m *ServiceMsgAdapter) Reply() string {
	return m.msg.Reply
}

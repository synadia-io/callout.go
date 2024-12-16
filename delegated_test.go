package callout

import (
	"encoding/json"
	"testing"
	"time"

	"callout/nst"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/suite"
)

func TestDelegated(t *testing.T) {
	suite.Run(t, new(DelegatedTestSuite))
}

type DelegatedTestSuite struct {
	suite.Suite
	dir  *nst.TestDir
	ns   *nst.NatsServer
	keys map[string]nkeys.KeyPair
	jwts map[string]string
}

func (s *DelegatedTestSuite) AddKey(name string, kind nkeys.PrefixByte) nkeys.KeyPair {
	kp, err := nkeys.CreatePair(kind)
	s.NoError(err)
	if s.keys == nil {
		s.keys = make(map[string]nkeys.KeyPair)
	}
	s.keys[name] = kp
	return kp
}

func (s *DelegatedTestSuite) GetKey(name string) nkeys.KeyPair {
	v := s.keys[name]
	s.NotNil(v)
	return v
}

func (s *DelegatedTestSuite) GetSeed(name string) []byte {
	v := s.keys[name]
	s.NotNil(v)
	seed, err := v.Seed()
	s.NoError(err)
	return seed
}

func (s *DelegatedTestSuite) GetPublicKey(name string) string {
	kp := s.GetKey(name)
	pk, err := kp.PublicKey()
	s.NoError(err)
	return pk
}

func (s *DelegatedTestSuite) SetupSuite() {
	s.dir = nst.NewTestDir(s.T())

	type ResolverConfig struct {
		Type string `json:"type"`
	}

	type Conf struct {
		HTTP          string            `json:"http"`
		Operator      string            `json:"operator"`
		SystemAccount string            `json:"system_account"`
		Resolver      ResolverConfig    `json:"resolver"`
		Preload       map[string]string `json:"resolver_preload"`
	}

	conf := Conf{}
	conf.HTTP = "0.0.0.0:-1"
	conf.Preload = make(map[string]string)
	conf.Resolver.Type = "mem"

	// system account
	s.AddKey("SYS", nkeys.PrefixByteAccount)
	sys := jwt.NewAccountClaims(s.GetPublicKey("SYS"))
	sys.Name = "SYS"
	sysJWT, err := sys.Encode(s.AddKey("O", nkeys.PrefixByteOperator))
	s.NoError(err)
	conf.Preload[s.GetPublicKey("SYS")] = sysJWT
	conf.SystemAccount = s.GetPublicKey("SYS")

	// operator
	oc := jwt.NewOperatorClaims(s.GetPublicKey("O"))
	oc.SystemAccount = s.GetPublicKey("SYS")
	conf.Operator, err = oc.Encode(s.GetKey("O"))
	s.NoError(err)

	// target account - where users will be placed
	s.AddKey("A", nkeys.PrefixByteAccount)
	ac := jwt.NewAccountClaims(s.GetPublicKey("A"))
	ac.Name = "A"
	accountJWT, err := ac.Encode(s.GetKey("O"))
	s.NoError(err)
	conf.Preload[s.GetPublicKey("A")] = accountJWT

	// the id of the service user that will connect to the service
	// account and will run the callout
	s.AddKey("AUTH_U", nkeys.PrefixByteUser)
	// the connection account - where users initially connect
	s.AddKey("AUTH", nkeys.PrefixByteAccount)
	auth := jwt.NewAccountClaims(s.GetPublicKey("AUTH"))
	auth.Name = "AUTH"
	auth.Authorization.AuthUsers.Add(s.GetPublicKey("AUTH_U"))
	auth.Authorization.AllowedAccounts.Add(s.GetPublicKey("A"))
	authJWT, err := auth.Encode(s.GetKey("O"))
	conf.Preload[s.GetPublicKey("AUTH")] = authJWT

	data, err := json.MarshalIndent(conf, "", "  ")
	s.NoError(err)

	configFile := s.dir.WriteServerConf(string(data))

	// start the server with the configuration
	s.ns = nst.NewNatsServer(s.T(), &natsserver.Options{
		ConfigFile: configFile,
		Debug:      true,
		Trace:      true,
		NoLog:      false,
	})
}

func (s *DelegatedTestSuite) ConnectAuthService() *nats.Conn {
	uc := jwt.NewUserClaims(s.GetPublicKey("AUTH_U"))
	token, err := uc.Encode(s.GetKey("AUTH"))
	s.NoError(err)
	nc, err := s.ns.MaybeConnect(nats.UserJWTAndSeed(token, string(s.GetSeed("AUTH_U"))))
	s.NoError(err)
	return nc
}

func (s *DelegatedTestSuite) ConnectSentinel(options ...nats.Option) (*nats.Conn, error) {
	id := nuid.Next()
	s.AddKey(id, nkeys.PrefixByteUser)
	uc := jwt.NewUserClaims(s.GetPublicKey(id))
	uc.Name = "Sentinel_" + id
	uc.Pub.Deny.Add(">")
	uc.Sub.Deny.Add(">")
	token, err := uc.Encode(s.GetKey("AUTH"))
	s.NoError(err)

	options = append(options, nats.UserJWTAndSeed(token, string(s.GetSeed(id))))
	return s.ns.MaybeConnect(options...)
}

func (s *DelegatedTestSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *DelegatedTestSuite) TestStart() {
	service := s.ConnectAuthService()
	defer service.Close()
	s.T().Log(service.ConnectedUrl())

	// this will fail
	_, err := s.ConnectSentinel(nats.MaxReconnects(1))
	s.Error(err)
	s.Contains(err.Error(), "timeout")

	keys := &Keys{
		ResponseSigner: s.GetKey("AUTH"),
	}

	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		return uc.Encode(s.GetKey("A"))
	}

	svc, err := AuthorizationService(service, authorizer, keys, nil, nil)
	s.NoError(err)
	s.NotNil(svc)
	defer svc.Stop()

	nc, err := s.ConnectSentinel(nats.MaxReconnects(1))
	s.NoError(err)
	defer nc.Close()
	r, err := nc.Request("$SYS.REQ.USER.INFO", []byte{}, time.Second*2)
	s.NoError(err)
	s.T().Logf("%v", string(r.Data))
}

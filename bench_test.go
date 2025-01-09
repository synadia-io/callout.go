package callout

import (
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/stretchr/testify/require"
)

type BenchSuite struct {
	m           *testing.TB
	dir         *nst.TestDir
	env         CalloutEnv
	ns          *nst.NatsServer
	service     []micro.Service
	serviceConn []*nats.Conn
}

func (bs *BenchSuite) Cleanup() {
	for _, c := range bs.serviceConn {
		c.Close()
	}
	for _, s := range bs.service {
		_ = s.Stop()
	}
	bs.ns.Shutdown()
	bs.dir.Cleanup()
}

func Setup(tb testing.TB, opts ...Option) *BenchSuite {
	dir := nst.NewTestDir(tb, "", "")
	env := NewBasicEnv(tb, dir)

	ns := nst.NewNatsServer(tb, &natsserver.Options{
		ConfigFile: dir.WriteFile("server.conf", env.GetServerConf()),
		Port:       -1,
		Debug:      false,
		Trace:      false,
		NoLog:      true,
	})

	bs := &BenchSuite{
		dir: dir,
		env: env,
		ns:  ns,
	}

	bs.AddService(tb, opts...)

	return bs
}

func (bs *BenchSuite) AddService(tb testing.TB, opts ...Option) {
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = bs.env.Audience()
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		return bs.env.EncodeUser("A", uc)
	}

	var err error
	nc, err := bs.ns.MaybeConnect(bs.env.ServiceUserOpts()...)
	require.NoError(tb, err)
	bs.serviceConn = append(bs.serviceConn, nc)

	opts = append(bs.env.ServiceOpts(),
		Authorizer(authorizer),
		Logger(nst.NewNilLogger()),
	)

	svc, err := AuthorizationService(nc, opts...)
	require.NoError(tb, err)
	require.NotNil(tb, svc)
	bs.service = append(bs.service, svc)
}

func Benchmark_PerfServiceHandler(b *testing.B) {
	bs := Setup(b)
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})
}

func Benchmark_PerfAsyncServiceHandler(b *testing.B) {
	bs := Setup(b, AsyncHandler())
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})
}

func Benchmark_PerfManyWorkers(b *testing.B) {
	bs := Setup(b, ServiceWorkers(10))
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})
}

func Benchmark_PerfManyServices(b *testing.B) {
	bs := Setup(b)
	for i := 0; i < 10; i++ {
		bs.AddService(b)
	}
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})
}

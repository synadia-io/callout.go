package callout

import (
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type BenchSuite struct {
	m        *testing.TB
	dir      *nst.TestDir
	env      CalloutEnv
	ns       nst.NatsServer
	services []*AuthorizationService
}

func (bs *BenchSuite) Cleanup() {
	for _, s := range bs.services {
		_ = s.Stop()
	}
	bs.ns.Shutdown()
	bs.dir.Cleanup()
}

func Setup(tb testing.TB, opts ...Option) *BenchSuite {
	dir := nst.NewTestDir(tb, "", "")
	env := NewBasicEnv(tb, dir)

	ns := nst.NewNatsServer(dir, &nst.Options{
		ConfigFile: dir.WriteFile("server.conf", env.GetServerConf()),
		Port:       4222,
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
	nc := bs.ns.RequireConnect(bs.env.ServiceUserOpts()...)
	require.NoError(tb, err)

	opts = append(bs.env.ServiceOpts(),
		Authorizer(authorizer),
		Logger(nst.NewNilLogger()),
	)

	svc, err := NewAuthorizationService(nc, opts...)
	require.NoError(tb, err)
	require.NotNil(tb, svc)
	bs.services = append(bs.services, svc)
}

func Benchmark_Auth(b *testing.B) {
	bs := Setup(b)
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	errs := 0
	for i := 0; i < b.N; i++ {
		nc, err := bs.ns.UntrackedConnection(opts...)
		if err != nil {
			errs++
		} else {
			defer nc.Close()
		}
	}

	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

func Benchmark_AuthParallel(b *testing.B) {
	bs := Setup(b)
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	errs := 0
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.UntrackedConnection(opts...)
			if err != nil {
				errs++
			} else {
				defer nc.Close()
			}
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

func Benchmark_AuthMultipleServiceEndpoints(b *testing.B) {
	bs := Setup(b, ServiceEndpoints(10))
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	errs := 0
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.UntrackedConnection(opts...)
			if err != nil {
				errs++
			} else {
				defer nc.Close()
			}
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

func Benchmark_AuthAsyncWorkers(b *testing.B) {
	bs := Setup(b, AsyncWorkers(10))
	for i := 0; i < 10; i++ {
		bs.AddService(b)
	}
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	errs := 0
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.UntrackedConnection(opts...)
			if err != nil {
				errs++
			} else {
				defer nc.Close()
			}
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

func Benchmark_AuthMultipleServices(b *testing.B) {
	bs := Setup(b)
	for i := 0; i < 10; i++ {
		bs.AddService(b)
	}
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	errs := 0
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.UntrackedConnection(opts...)
			if err != nil {
				errs++
			} else {
				defer nc.Close()
			}
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

package callout

import (
	"fmt"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type BenchSuite struct {
	m           *testing.TB
	dir         *nst.TestDir
	env         CalloutEnv
	ns          *nst.NatsServer
	services    []*AuthorizationService
	serviceConn []*nats.Conn
}

func (bs *BenchSuite) Cleanup() {
	for _, c := range bs.serviceConn {
		c.Close()
	}
	for _, s := range bs.services {
		_ = s.Stop()
	}
	bs.ns.Shutdown()
	bs.dir.Cleanup()
}

type Samples struct {
	tb       *testing.B
	start    time.Time
	duration time.Duration
	avg      time.Duration
	max      float64
}

func NewSamples(tb *testing.B) *Samples {
	return &Samples{
		tb:    tb,
		start: time.Now(),
	}
}

func (b *Samples) Done() {
	b.duration = time.Since(b.start)
	b.avg = b.duration / time.Duration(b.tb.N)
	b.max = float64(time.Second / b.avg)
}

func (b *Samples) String() string {
	return fmt.Sprintf("%d ops - total time: %v avg: %v max clients: ~%v", b.tb.N, b.duration, b.avg, b.max)
}

func (b *Samples) Print(format string) {
	b.tb.Logf(format, b)
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

	ok := 0
	sample := NewSamples(b)
	for i := 0; i < b.N; i++ {
		_, err := bs.ns.MaybeConnect(opts...)
		if err == nil {
			ok++
		}
	}

	sample.Done()
	sample.Print("%v")
	b.Logf("OK %v", ok)
}

func Benchmark_AuthParallel(b *testing.B) {
	bs := Setup(b)
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	ok := 0
	sample := NewSamples(b)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := bs.ns.MaybeConnect(opts...)
			if err == nil {
				ok++
			}
		}
	})
	sample.Done()
	sample.Print("%v")
	b.Logf("OK %v", ok)
}

func Benchmark_AuthMultipleServiceEndpoints(b *testing.B) {
	bs := Setup(b, ServiceEndpoints(10))
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()

	sample := NewSamples(b)
	ok := 0
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := bs.ns.MaybeConnect(opts...)
			if err == nil {
				ok++
			}
		}
	})

	sample.Done()
	sample.Print("%v")
	b.Logf("OK %v", ok)
}

func Benchmark_AuthAsyncWorkers(b *testing.B) {
	bs := Setup(b, AsyncWorkers(10))
	for i := 0; i < 10; i++ {
		bs.AddService(b)
	}
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()
	sample := NewSamples(b)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})

	sample.Done()
	sample.Print("%v")
}

func Benchmark_AuthMultipleServices(b *testing.B) {
	bs := Setup(b)
	for i := 0; i < 10; i++ {
		bs.AddService(b)
	}
	defer bs.Cleanup()

	opts := []nats.Option{nats.UserInfo("hello", "world"), nats.MaxReconnects(0)}
	opts = append(opts, bs.env.UserOpts()...)
	b.ResetTimer()
	sample := NewSamples(b)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := bs.ns.MaybeConnect(opts...)
			require.NoError(b, err)
			require.NotNil(b, nc)
		}
	})

	sample.Done()
	sample.Print("%v")
}

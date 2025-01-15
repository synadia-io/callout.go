package callout

import (
	"sync"
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func Benchmark_EncodeJwts(b *testing.B) {
	akp, err := nkeys.CreateAccount()
	require.NoError(b, err)

	ukp, err := nkeys.CreateUser()
	require.NoError(b, err)

	upk, err := ukp.PublicKey()
	require.NoError(b, err)
	b.ResetTimer()
	sample := NewSamples(b)

	for i := 0; i < b.N; i++ {
		uc := jwt.NewUserClaims(upk)
		uc.Audience = "$G"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		_, err = uc.Encode(akp)
		require.NoError(b, err)
	}

	sample.Done()
	sample.Print("%v jwts/sec")
}

func Benchmark_ParallelEncodeJwts(b *testing.B) {
	akp, err := nkeys.CreateAccount()
	require.NoError(b, err)

	ukp, err := nkeys.CreateUser()
	require.NoError(b, err)

	upk, err := ukp.PublicKey()
	require.NoError(b, err)
	b.ResetTimer()
	sample := NewSamples(b)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			uc := jwt.NewUserClaims(upk)
			uc.Audience = "$G"
			uc.Pub.Allow.Add(nst.UserInfoSubj)
			uc.Sub.Allow.Add("_INBOX.>")
			uc.Expires = time.Now().Unix() + 90
			_, err = uc.Encode(akp)
			require.NoError(b, err)
		}
	})
	sample.Done()
	sample.Print("%v jwts/sec")
}

func Benchmark_ServiceHandler(b *testing.B) {
	// create some keys
	skp, err := nkeys.CreateServer()
	require.NoError(b, err)
	spk, err := skp.PublicKey()
	require.NoError(b, err)

	ukp, err := nkeys.CreateUser()
	require.NoError(b, err)
	upk, err := ukp.PublicKey()
	require.NoError(b, err)

	akp, err := nkeys.CreateAccount()
	require.NoError(b, err)

	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "$G"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		return uc.Encode(akp)
	}

	callout := &AuthorizationService{opts: &Options{
		Authorizer:        authorizer,
		Logger:            nst.NewNilLogger(),
		ResponseSignerKey: akp,
		ErrCallback:       func(err error) {},
	}}

	b.ResetTimer()

	sample := NewSamples(b)

	for i := 0; i < b.N; i++ {
		r := jwt.NewAuthorizationRequestClaims(spk)
		r.UserNkey = upk
		r.Audience = "nats-authorization-request"
		r.Server.ID = spk
		token, err := r.Encode(skp)
		require.NoError(b, err)

		msg := nats.Msg{Data: []byte(token)}
		mr := NewNoNetServiceMsgAdapter(&msg)
		callout.ServiceHandler(mr)
	}

	sample.Done()
	sample.Print("%v clients/sec")
}

func Benchmark_ParallelServiceHandler(b *testing.B) {
	// create some keys
	skp, err := nkeys.CreateServer()
	require.NoError(b, err)
	spk, err := skp.PublicKey()
	require.NoError(b, err)

	ukp, err := nkeys.CreateUser()
	require.NoError(b, err)
	upk, err := ukp.PublicKey()
	require.NoError(b, err)

	akp, err := nkeys.CreateAccount()
	require.NoError(b, err)

	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		uc.Audience = "$G"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		return uc.Encode(akp)
	}

	callout := &AuthorizationService{opts: &Options{
		Authorizer:        authorizer,
		Logger:            nst.NewNilLogger(),
		ResponseSignerKey: akp,
		ErrCallback:       func(err error) {},
	}}

	b.ResetTimer()

	sample := NewSamples(b)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := jwt.NewAuthorizationRequestClaims(spk)
			r.UserNkey = upk
			r.Audience = "nats-authorization-request"
			r.Server.ID = spk
			token, err := r.Encode(skp)
			require.NoError(b, err)

			msg := nats.Msg{Data: []byte(token)}
			mr := NewNoNetServiceMsgAdapter(&msg)
			callout.ServiceHandler(mr)
		}
	})

	sample.Done()
	sample.Print("%v clients/sec")
}

func Benchmark_MicroRequestReply(b *testing.B) {
	ns := nst.NewNatsServer(b, &natsserver.Options{})
	defer ns.Shutdown()

	srv := ns.Connect()
	config := micro.Config{
		Name:        "sample",
		Version:     "0.0.1",
		Description: "rr",
		Endpoint: &micro.EndpointConfig{
			Subject: "q",
			Handler: micro.HandlerFunc(func(msg micro.Request) {
				_ = msg.Respond(nil)
			}),
		},
	}
	_, _ = micro.AddService(srv, config)

	client := ns.Connect()
	b.ResetTimer()

	sample := NewSamples(b)
	for i := 0; i < b.N; i++ {
		_, err := client.Request("q", nil, time.Second)
		require.NoError(b, err)
	}
	sample.Done()
	sample.Print("%v requests/sec")
}

func Benchmark_MicroAsyncRequestReply(b *testing.B) {
	ns := nst.NewNatsServer(b, &natsserver.Options{})
	defer ns.Shutdown()

	srv := ns.Connect()
	ch := make(chan micro.Request, 5000)
	for i := 0; i < 10; i++ {
		go func() {
			for {
				select {
				case msg, ok := <-ch:
					if !ok {
						return
					}
					_ = msg.Respond(nil)
				}
			}
		}()
	}
	config := micro.Config{
		Name:        "sample",
		Version:     "0.0.1",
		Description: "rr",
		Endpoint: &micro.EndpointConfig{
			Subject: "q",
			Handler: micro.HandlerFunc(func(msg micro.Request) {
				ch <- msg
			}),
		},
	}
	_, _ = micro.AddService(srv, config)

	client := ns.Connect()
	b.ResetTimer()

	sample := NewSamples(b)
	var wg sync.WaitGroup
	wg.Add(b.N)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Request("q", nil, time.Second)
			require.NoError(b, err)
			wg.Done()
		}
	})
	wg.Wait()

	sample.Done()
	close(ch)
	sample.Print("%v requests/sec")
}

func Benchmark_RequestReply(b *testing.B) {
	ns := nst.NewNatsServer(b, &natsserver.Options{})
	defer ns.Shutdown()

	srv := ns.Connect()
	_, _ = srv.Subscribe("q", func(m *nats.Msg) {
		_ = m.Respond(nil)
	})

	client := ns.Connect()
	b.ResetTimer()

	sample := NewSamples(b)
	for i := 0; i < b.N; i++ {
		_, err := client.Request("q", nil, time.Second)
		require.NoError(b, err)
	}
	sample.Done()
	sample.Print("%v requests/sec")
}

func Benchmark_ParallelConnect(b *testing.B) {
	ns := nst.NewNatsServer(b, &natsserver.Options{Port: -1})
	defer ns.Shutdown()

	b.ResetTimer()
	sample := NewSamples(b)
	ok := 0
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := ns.MaybeConnect()
			if err == nil {
				ok++
			}
		}
	})
	sample.Done()
	sample.Print("%v connects/sec")
	b.Logf("ok=%d", ok)
}

func Benchmark_ParallelRequestReply(b *testing.B) {
	ns := nst.NewNatsServer(b, &natsserver.Options{})
	defer ns.Shutdown()

	srv := ns.Connect()
	_, _ = srv.Subscribe("q", func(m *nats.Msg) {
		_ = m.Respond(nil)
	})

	client := ns.Connect()
	b.ResetTimer()

	sample := NewSamples(b)
	var wg sync.WaitGroup
	wg.Add(b.N)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Request("q", nil, time.Second)
			require.NoError(b, err)
			wg.Done()
		}
	})
	wg.Wait()
	sample.Done()
	sample.Print("%v requests/sec")
}

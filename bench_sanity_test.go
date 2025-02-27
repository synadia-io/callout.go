// Copyright 2025 Synadia Communications, Inc
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callout

import (
	"testing"
	"time"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
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

	for i := 0; i < b.N; i++ {
		uc := jwt.NewUserClaims(upk)
		uc.Audience = "$G"
		uc.Pub.Allow.Add(nst.UserInfoSubj)
		uc.Sub.Allow.Add("_INBOX.>")
		uc.Expires = time.Now().Unix() + 90
		_, err = uc.Encode(akp)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "jwts/sec")
}

func Benchmark_ParallelEncodeJwts(b *testing.B) {
	akp, err := nkeys.CreateAccount()
	require.NoError(b, err)

	ukp, err := nkeys.CreateUser()
	require.NoError(b, err)

	upk, err := ukp.PublicKey()
	require.NoError(b, err)
	b.ResetTimer()

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

	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "jwts/sec")
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

	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
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

	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "auths/sec")
}

func Benchmark_MicroRequestReply(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	srv := ns.RequireConnect()
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

	client := ns.RequireConnect()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := client.Request("q", nil, time.Second)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "reqrep/sec")
}

func Benchmark_MicroAsyncRequestReply(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	srv := ns.RequireConnect()
	ch := make(chan micro.Request, 5000)
	defer close(ch)

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

	client := ns.RequireConnect()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Request("q", nil, time.Second)
			require.NoError(b, err)

		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "reqrep/sec")
}

func Benchmark_RequestReply(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	srv := ns.RequireConnect()
	_, _ = srv.Subscribe("q", func(m *nats.Msg) {
		_ = m.Respond(nil)
	})

	client := ns.RequireConnect()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := client.Request("q", nil, time.Second)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "reqrep/sec")
}

func Benchmark_ParallelRequestReply(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	srv := ns.RequireConnect()
	_, _ = srv.Subscribe("q", func(m *nats.Msg) {
		_ = m.Respond(nil)
	})

	client := ns.RequireConnect()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Request("q", nil, time.Second)
			require.NoError(b, err)
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "reqrep/sec")
}

func Benchmark_Connect(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	errs := 0
	u := ns.NatsURLs()[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nc, err := nats.Connect(u)
		if err == nil {
			defer nc.Close()
		} else {
			errs++
		}
	}
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "conns/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

func Benchmark_ParallelConnect(b *testing.B) {
	dir := nst.NewTestDir(b, "", "bench")
	defer dir.Cleanup()
	ns := nst.NewNatsServer(dir, &nst.Options{Port: -1})
	defer ns.Shutdown()

	errs := 0
	u := ns.NatsURLs()[0]
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nc, err := nats.Connect(u)
			if err != nil {
				errs++
			} else {
				defer nc.Close()
			}
		}
	})
	b.ReportMetric(float64(time.Second/(b.Elapsed()/time.Duration(b.N))), "conns/sec")
	if errs > 0 {
		b.ReportMetric(float64(errs), "failed")
	}
}

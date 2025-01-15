package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aricart/callout.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func loadAndParseKeys(fp string) (nkeys.KeyPair, error) {
	if fp == "" {
		return nil, errors.New("key file required")
	}
	seed, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}
	if !bytes.HasPrefix(seed, []byte{'S', 'A'}) {
		return nil, fmt.Errorf("key must be an account private key")
	}
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %w", err)
	}
	return kp, nil
}

func getConnectionOptions(fp string) ([]nats.Option, error) {
	if fp == "" {
		return nil, errors.New("creds file required")
	}
	return []nats.Option{nats.UserCredentials(fp)}, nil
}

func main() {
	// load the creds, and keys
	var credsFp, calloutKeyFp, issuerKeyFp string
	flag.StringVar(&credsFp, "creds", "", "creds file for the service")
	flag.StringVar(&calloutKeyFp, "callout-issuer", "", "key for signing callout responses")
	flag.StringVar(&issuerKeyFp, "issuer", "", "key for signing users")
	flag.Parse()

	cKP, err := loadAndParseKeys(calloutKeyFp)
	if err != nil {
		panic(fmt.Errorf("error loading callout issuer: %w", err))
	}
	aKP, err := loadAndParseKeys(issuerKeyFp)
	if err != nil {
		panic(fmt.Errorf("error loading callout issuer: %w", err))
	}

	// the authorizer function
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		uc := jwt.NewUserClaims(req.UserNkey)
		if req.ConnectOptions.Name == "bad" {
			// ignore this user
			return "", nil
		}
		fmt.Println("namer: ", uc.Name, "")
		return uc.Encode(aKP)
	}

	// connect the service with the creds
	opts, err := getConnectionOptions(credsFp)
	if err != nil {
		panic(fmt.Errorf("error loading creds: %w", err))
	}
	nc, err := nats.Connect("nats://localhost:4222", opts...)
	if err != nil {
		panic(fmt.Errorf("error connecting: %w", err))
	}
	defer nc.Close()

	// start the service
	_, err = callout.NewAuthorizationService(nc, callout.Authorizer(authorizer), callout.ResponseSignerKey(cKP))

	// don't exit until sigterm
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
}

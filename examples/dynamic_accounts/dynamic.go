package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aricart/callout.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func loadAndParseKeys(fp string, kind byte) (nkeys.KeyPair, error) {
	if fp == "" {
		return nil, errors.New("key file required")
	}
	seed, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}
	if !bytes.HasPrefix(seed, []byte{'S', kind}) {
		return nil, fmt.Errorf("key must be a private key")
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

func UpdateAccount(nc *nats.Conn, token string) (*ResolverUpdateResponse, error) {
	var r ResolverUpdateResponse
	m, err := nc.Request("$SYS.REQ.CLAIMS.UPDATE", []byte(token), time.Second*2)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(m.Data, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

type UpdateData struct {
	Account string `json:"account"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ResolverResponse struct {
	Error  *ErrorDetails `json:"error,omitempty"`
	Server ServerDetails `json:"server"`
}

type ServerDetails struct {
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	ID        string    `json:"id"`
	Version   string    `json:"ver"`
	Jetstream bool      `json:"jetstream"`
	Flags     int       `json:"flags"`
	Sequence  int       `json:"seq"`
	Time      time.Time `json:"time"`
}

type ErrorDetails struct {
	Account     string `json:"account"`
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type ResolverUpdateResponse struct {
	ResolverResponse
	UpdateData UpdateData `json:"data"`
}

func main() {
	// load the creds, and keys
	var credsFp, sysCreds, calloutKeyFp, operatorKeyFp string
	flag.StringVar(&credsFp, "creds", "./service.creds", "creds file for the service")
	flag.StringVar(&sysCreds, "sys", "./sys.creds", "system creds")
	flag.StringVar(&calloutKeyFp, "callout-issuer", "./C.nk", "key for signing callout responses")
	flag.StringVar(&operatorKeyFp, "operator-key", "./operator.nk", "key for creating accounts")
	flag.Parse()

	okp, err := loadAndParseKeys(operatorKeyFp, 'O')
	if err != nil {
		panic(err)
	}

	sysOpts, err := getConnectionOptions(sysCreds)
	if err != nil {
		panic(err)
	}
	sys, err := nats.Connect("nats://localhost:4222", sysOpts...)
	if err != nil {
		panic(err)
	}

	_, _ = sys.Subscribe("$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP", func(m *nats.Msg) {
		chunks := strings.Split(m.Subject, ".")
		id := chunks[3]
		fmt.Println(id)
	})

	// this creates a new account named as specified returning
	// the key used to sign users
	createAccount := func(name string) (nkeys.KeyPair, error) {
		kp, err := nkeys.CreateAccount()
		if err != nil {
			return nil, err
		}
		pk, err := kp.PublicKey()
		if err != nil {
			return nil, err
		}
		ac := jwt.NewAccountClaims(pk)
		ac.Name = name
		token, err := ac.Encode(okp)
		if err != nil {
			return nil, err
		}
		r, err := UpdateAccount(sys, token)
		if err != nil {
			return nil, err
		}
		// verify that the update worked
		if r.UpdateData.Code != 200 {
			return nil, fmt.Errorf("error creating account: %s", r.Error.Description)
		}
		return kp, nil
	}

	// keep a map of account names to keys - this would likely need to be more
	// sophisticated, and be persistent. Likely some sort of cleanup logic would
	// have to be added to delete (set connections to 0) and possibly remove from
	// resolver once accounts are vacated - this is an exercise for the reader.
	accounts := make(map[string]nkeys.KeyPair)

	// load the callout key
	cKP, err := loadAndParseKeys(calloutKeyFp, 'A')
	if err != nil {
		panic(fmt.Errorf("error loading callout issuer: %w", err))
	}

	// the authorizer function
	authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
		// reading the account name from the token, likely this will be
		// encoded string with more information
		accountName := req.ConnectOptions.Token
		if accountName == "" {
			// fail
			return "", errors.New("no account name")
		}
		// see if we have this account
		akp, ok := accounts[accountName]
		if !ok {
			// create it and push it
			akp, err = createAccount(accountName)
			if err != nil {
				return "", err
			}
			accounts[accountName] = akp
		}
		// issue the user
		uc := jwt.NewUserClaims(req.UserNkey)
		return uc.Encode(akp)
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

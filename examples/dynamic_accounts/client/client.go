package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

func getConnectionOptions(fp string) ([]nats.Option, error) {
	if fp == "" {
        return nil, errors.New("creds file required")
	}
	return []nats.Option{}, nil
}

func main() {
	// load the creds, and keys
	var credsFp, accountName string
	// sentinel creds
	flag.StringVar(&credsFp, "creds", "./sentinel.creds", "creds file for the client")
	// the account the user wants to be placed in
	flag.StringVar(&accountName, "account-name", "", "account name")
	flag.Parse()

	// connect
	opts, err := getConnectionOptions(credsFp)

	opts = append(opts, nats.Token(accountName))
	if err != nil {
		panic(err)
	}
	nc, err := nats.Connect("nats://localhost:4222", opts...)
	if err != nil {
		panic(err)
	}
	defer nc.Close()

	// find out where we got placed
	r, err := nc.Request("$SYS.REQ.USER.INFO", nil, time.Second*2)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(r.Data))
}

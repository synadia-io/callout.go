## Dynamic Accounts (Proof of Concept)

### What do we do here
* This example runs NATS in decentralized authentication (aka operator mode)
* `generate.sh` create a NATS operator, config files, accounts and user and configures the auth callout
* Account C is configured to receive auth callout calls which are processed by the the callout service in `delegated_example.go`
* Client.go  receives an `-account-name B` and passes it to the connection in the `token` field
* The auth callout service
    * Checks if the login token is present on the connection
    * Creates a new account named accordingly using the operator nkey to sign the account 
    * Installs the account and extracts the account nkey
    * Creates a user JWT in the new account and signs it

### Execute example
Using a NATS resolver it is possible to create accounts on the fly to place
users. This has an interesting niche use-case. All of it can be accomplished via
a callout, so long as the callout can create an account, deploy it, and create
the user within the authentication window.

Worse that could happen is the first connection could fail, but eventually the
server would be aware of the account, and the connection would proceed.

And a [Go program](dynamic.go) that uses the library and the results of the
above script to run a service. And a client [Go Program](client/client.go)

To run, execute the generate.sh script.

```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run dynamic.go -operator-key /tmp/DA/operator.nk -sys /tmp/DA/sys.creds -callout-issuer /tmp/DA/C.nk -creds /tmp/DA/service.creds

# in another terminal start client.go 
# The -account-name parameter will be send as the  token in the client connection
cd client
go run client.go -account-name B -creds /tmp/DA/sentinel.creds

{"server":{"name":"ND4SGVPVMOHYB3BISPYKWE3RUSILPCAFBV74AEFYFJBRWSXPN6FGKSGG","host":"0.0.0.0","id":"ND4SGVPVMOHYB3BISPYKWE3RUSILPCAFBV74AEFYFJBRWSXPN6FGKSGG","ver":"2.11.0-dev","jetstream":false,"flags":0,"seq":127,"time":"2025-02-04T20:30:09.615143Z"},"data":{"user":"B","account":"AADWDO5UGBLQT2MBC4NCUUHE34TG6KED47OHCPWWXTRHCFOKXGWTRO4F"}}

# The only user allowed in with going through auth callout is service
nats -s localhost:4222 --creds /tmp/DA/service.creds pub hello hi
13:03:13 Published 2 bytes to "hello"
```


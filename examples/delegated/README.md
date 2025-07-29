## Delegated Authentication

### What do we do here
* This example runs NATS in decentralized authentication mode (aka operator mode)
* `generate.sh` creates a NATS operator, config files, accounts and user and configures the auth callout
* Account C is configured to receive auth callout calls which are processed by the the callout service in `delegated_example.go`
* Authenticated user are placed in account A
* The authentication logic itself is trivial for this example. No external services are being called. 
    * The auth callout service checks the connection name: `req.ConnectOptions.Name`
    * All connection are allowed in unless the connection name is set to `bad`


### Execute example
Decentralized authentication is a bit more complex mostly because the callout configuration takes place on the account JWTs. Here's a [script that builds an environment](generate.sh).

And a [Go program](delegated_example.go) that uses the library and the results of the above 
script to run a service.

To run, execute the generate.sh script.

```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run delegated_example.go --creds /tmp/DA/service.creds --callout-issuer /tmp/DA/C.nk --issuer /tmp/DA/A.nk 

# in another terminal try - callout will reject connection named 'bad'
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds --connection-name=bad pub hello hi
nats: error: read tcp 127.0.0.1:51120->127.0.0.1:4222: i/o timeout

# but works for any other connection
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds pub hello hi
13:03:13 Published 2 bytes to "hello"
```




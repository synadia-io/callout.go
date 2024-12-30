## Delegated Authentication

The delegated authentication is a bit more complex mostly because the callout configuration
takes place on the account JWTs. Here's a [script that builds an environment](generate.sh).

And a [Go program](delegated_example.go) that uses the library and the results of the above 
script to run a service.

To run, execute the script, and then
```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run callout.go --creds /tmp/DA/service.creds --callout-issuer /tmp/DA/C.nk --issuer /tmp/DA/A.nk 

# in another terminal try - callout will reject user named 'bad'
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds --connection-name=bad pub hello hi
nats: error: read tcp 127.0.0.1:51120->127.0.0.1:4222: i/o timeout

# but work for anything else
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds pub hello hi
13:03:13 Published 2 bytes to "hello"






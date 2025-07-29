## Delegated Authentication with default sentinel

### What do we do here
* This example runs NATS in decentralized authentication mode (aka operator mode)
* `generate.sh` creates a NATS operator, config files, accounts and user and configures the auth callout
* Passing the sentinel credentials can be inconvenient. When there is only a single auth callout service configured, setting a default sentinel is a useful configuration.    
    * A bearer JWT is created for user `sentinel` and set as default sentinel in the server configuration. 
    * All connection which do not present a JWT will use the default sentinel.
    * This allows us to skip providing the `sentinal.creds` in the connection
* Account C is configured to receive auth callout calls which are processed by the the callout service in `delegated_example.go`
* Authenticated users are placed in account A
* The authentication logic itself is trivial for this example. No external services are being called. 
    * The auth callout service checks user name and password
    * When user name and password are identical the connection is allowed
    * All other connections are rejected 

### Execute example
Decentralized authentication is a bit more complex mostly because the callout configuration takes place on the account JWTs. Here's a [script that builds an environment](generate.sh).

And a [Go program](delegated_default_sentinel.go) that uses the library and the results of the above script to run a service.

To run, execute the generate.sh script.

```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run delegated_default_sentinel.go --creds /tmp/DA/service.creds --callout-issuer /tmp/DA/C.nk --issuer /tmp/DA/A.nk 

# in another terminal try - callout will allow connections if user name and password match
nats -s localhost:4222 --user=ACME --password=ACME pub hello hi
13:03:13 Published 2 bytes to "hello"

# All other will be rejected
nats -s localhost:4222 --user=ACME --password=Hi pub hello hi
nats: error: read tcp 127.0.0.1:51120->127.0.0.1:4222: i/o timeout
```

## Using a default sentinel
Support for a default sentinel (example below) has been added in nats-server 2.11.2. This option is only allowed when the server is running in distributed authentication mode.

The default sentinel MUST BE marked as a bearer JWT. 
````
nsc edit user sentinel --bearer
````

When a connection does not present a JWT the default_sentinel is used. This allows for:
1. A default user similar to `no_auth_user` in distributed authentication mode.
2. Forwarding connection to a default auth callout account, such that lightweight client, e.g. web clients, do not need to obtain the sentinel.creds file.


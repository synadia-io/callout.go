## Delegated Authentication

### What do we do here
* There examples runs NATS in operator mode (aka distributed security)
* generate.sh create a NATS operator, config files, accounts and user and configures the auth callout
* Account C is configured to receive auth callout calls which are processed by the the callout service in `delegated_example.go`
* Authenticated user are installed in account A
* The authentication logic itself is trivial for this example. No external services are being called. 
    * The auth service checks the connection name `req.ConnectOptions.Name`
    * All connection are allowed in unless the connection name is `bad`


### Execute example
The delegated authentication is a bit more complex mostly because the callout configuration
takes place on the account JWTs. Here's a [script that builds an environment](generate.sh).

And a [Go program](delegated_example.go) that uses the library and the results of the above 
script to run a service.

To run, execute the generate.sh script.

```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run delegated_example.go --creds /tmp/DA/service.creds --callout-issuer /tmp/DA/C.nk --issuer /tmp/DA/A.nk 

# in another terminal try - callout will reject user named 'bad'
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds --connection-name=bad pub hello hi
nats: error: read tcp 127.0.0.1:51120->127.0.0.1:4222: i/o timeout

# but work for any other connection
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds pub hello hi
13:03:13 Published 2 bytes to "hello"
```

## Using a default sentinel
Alternatively to passing the sentinel.creds NATS allows for configuring a default sentinel in the server.conf. The JWT presented as sentinel must be a bearer JWT.

`generate.sh` creates a sentinel_bearer.creds for this purpose.

Add to server.conf (replace the JWT with the JWT from sentinel_bearer.creds )
````
"default_sentinel": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJDUEhWT1ZPWElJUFdKRDJZVkw1T0pIS0lLTFc2R05aWDdYQUNNN0hGWDNIVUZWVjRBNEFRIiwiaWF0IjoxNzUyNjMxODYzLCJpc3MiOiJBQjVYVklONEZaTllYTlYyWDZYN0ZWVlJFN0E0RUQ3M0JZNEVOUFJOQUdLS0pRN1JXUjJRNUFTUyIsIm5hbWUiOiJzZW50aW5lbCIsInN1YiI6IlVBMklZNlQ0Q1dOUlNFWVFZTkhQVzZIWEhCWkFOQ0ZaT0xMUVk3TlJWSlNYT0kzVUVZU1RaS0hGIiwibmF0cyI6eyJwdWIiOnsiZGVueSI6WyJcdTAwM2UiXX0sInN1YiI6eyJkZW55IjpbIlx1MDAzZSJdfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.onyBWBv1a0g4HYS7nkYk59bsHgodtmUeoeWH72PVI76QjZzrGcR4iTeefjTc8pTqK0FibkLttpWhCN11IkktDg",
`````

````
# Now the sentinel creds are added from default_sentinel when not presented by the client
nats -s localhost:4222 pub hello hi
````



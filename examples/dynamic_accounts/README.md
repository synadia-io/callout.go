## Dynamic Accounts (Proof of Concept)

Using a NATS resolver it is possible to create accounts on the fly to place
users. This has an interesting niche use-case. All of it can be accomplished via
a callout, so long as the callout can create an account, deploy it, and create
the user within the authentication window.

Worse that could happen is the first connection could fail, but eventually the
server would be aware of the account, and the connection would proceed.

And a [Go program](dynamic.go) that uses the library and the results of the
above script to run a service. And a client [Go Program](client/client.go)

To run, execute the generate.sh script and install the C account. Either by adding it to the preload section or running nsc push (see below)

```bash
# Install C in preload (or push after running the nats server)
nsc describe account C
# Add to the preload section of server.conf
# <account ID>:<Content of C.jwt - without the comment>

# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# push the C account (if not installed in preload)
nsc -u nats://localhost:4222 push

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

## Using a default sentinel
Alternatively to passing the sentinel.creds NATS allows for configuring a default sentinel in the server.conf. The JWT presented as sentinel must be a bearer JWT.

The generate.sh creates a sentinel_bearer.creds for this purpose.


For example:
```
"default_sentinel": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJDUEhWT1ZPWElJUFdKRDJZVkw1T0pIS0lLTFc2R05aWDdYQUNNN0hGWDNIVUZWVjRBNEFRIiwiaWF0IjoxNzUyNjMxODYzLCJpc3MiOiJBQjVYVklONEZaTllYTlYyWDZYN0ZWVlJFN0E0RUQ3M0JZNEVOUFJOQUdLS0pRN1JXUjJRNUFTUyIsIm5hbWUiOiJzZW50aW5lbCIsInN1YiI6IlVBMklZNlQ0Q1dOUlNFWVFZTkhQVzZIWEhCWkFOQ0ZaT0xMUVk3TlJWSlNYT0kzVUVZU1RaS0hGIiwibmF0cyI6eyJwdWIiOnsiZGVueSI6WyJcdTAwM2UiXX0sInN1YiI6eyJkZW55IjpbIlx1MDAzZSJdfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.onyBWBv1a0g4HYS7nkYk59bsHgodtmUeoeWH72PVI76QjZzrGcR4iTeefjTc8pTqK0FibkLttpWhCN11IkktDg",
```
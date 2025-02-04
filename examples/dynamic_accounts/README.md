## Dynamic Accounts (Proof of Concept)

Using a NATS resolver it is possible to create accounts on the fly to place
users. This has an interesting niche use-case. All of it can be accomplished via
a callout, so long as the callout can create an account, deploy it, and create
the user within the authentication window.

Worse that could happen is the first connection could fail, but eventually the
server would be aware of the account, and the connection would proceed.

And a [Go program](dynamic.go) that uses the library and the results of the
above script to run a service. And a client [Go Program](client/client.go)

To run, execute the script, and then

```bash
# the script will put things in /tmp/DA
nats-server -c /tmp/DA/server.conf

# in another terminal run the callout service:
go run dynamic.go -operator-key /tmp/DA/operator.nk -sys /tmp/DA/sys.creds -callout-issuer /tmp/DA/C.nk -creds /tmp/DA/service.creds

# in another terminal try the callout with the client program:
cd client
go run client.go -account-name B -creds /tmp/DA/sentinel.creds

{"server":{"name":"ND4SGVPVMOHYB3BISPYKWE3RUSILPCAFBV74AEFYFJBRWSXPN6FGKSGG","host":"0.0.0.0","id":"ND4SGVPVMOHYB3BISPYKWE3RUSILPCAFBV74AEFYFJBRWSXPN6FGKSGG","ver":"2.11.0-dev","jetstream":false,"flags":0,"seq":127,"time":"2025-02-04T20:30:09.615143Z"},"data":{"user":"B","account":"AADWDO5UGBLQT2MBC4NCUUHE34TG6KED47OHCPWWXTRHCFOKXGWTRO4F"}}
# but work for anything else
nats -s localhost:4222 --creds /tmp/DA/sentinel.creds pub hello hi
13:03:13 Published 2 bytes to "hello"
```

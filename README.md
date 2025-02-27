# Callout.go

[![Coverage Status](https://coveralls.io/repos/github/aricart/callout.go/badge.svg?branch=main)](https://coveralls.io/github/aricart/callout.go?branch=main)
[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/aricart/callout.go)](https://goreportcard.com/report/github.com/aricart/callout.go)

This library implements a small framework for writing AuthCallout services for
NATS.

An AuthCallout is a service that generates an authorization for a user based on
an external criteria. There are five aspects to a callout:

1. Receiving an authorization request
1. Decoding and validating an authorization request
1. Generating a user JWT based on the authorization request information
1. Packaging an authorization response
1. Sending the authorization response to the server

With the exception of step #3, all the other operations are completely
boilerplate. While not complicated, it requires a careful understanding of the
callout process and the features it provides to make the callout process secure.

The callout library simply requires a custom function implementation for step #3
(generating an user JWT), and handles all the other minutia automatically.

The library is implemented using the NATS services framework which enables you
to easily horizontally scale the service to meet your cluster's demand.

# High-level Overview

A callout simply issues a user JWT from a request from the server. So at it's
most basic it is really just a request that receives an encoded
[jwt.AuthorizationRequestClaims](https://pkg.go.dev/github.com/nats-io/jwt/v2#AuthorizationRequestClaims)
which contains a
[jwt.AuthorizationRequest](https://pkg.go.dev/github.com/nats-io/jwt/v2#AuthorizationRequest).

The server may have transmitted the request encrypted if the callout
configuration specifies an encryption public key.

After possibly decrypting the request and decoding the
`jwt.AuthorizationRequestClaims`, some checks are performed on the request. if
its valid, and use the data provided in the `jwt.AuthorizationRequest`. The
request provides all the connection options specified by the client as well as
TLS information, and as additional information from the server. Of importance is
the `UserNKey`, which specifies the ID that must be assigned to the user if the
authorization succeeds. Typically, clients encode additional information into
the information in the `token` field.

Limits and permissions are then translated into a
[jwt.UserClaims](https://pkg.go.dev/github.com/nats-io/jwt/v2#UserClaims) which
describes the limits and permissions for the user within NATS.

Next, the callout service generates a
[jwt.AuthorizationResponseClaims](https://pkg.go.dev/github.com/nats-io/jwt/v2#AuthorizationResponseClaims)
which embeds a
[jwt.AuthorizationResponse](https://pkg.go.dev/github.com/nats-io/jwt/v2#AuthorizationResponse)
which either includes the generated JWT token (a string) or an error message. If
an error message is set, this message will be printed by the NATS server, but
NOT transmitted to the user. Reasoning for rejecting a user shouldn't be
forwarded. Note that typically if the user is rejected, the best practice is to
_drop_ the request after logging a message. This will timeout the authorization
request and reject the user. The timeout introduces a delay that to slow down
users that are rejected.

Finally, if the callout is using encryption, it must encrypt the encoded
`jwt.AuthorizationResponseClaim` using the server's public key, and sending the
response back to the server. The server in turn, validates the response and if
all looks good, uses the generated user JWT as the permissions to assign to the
user connecting it to NATS.

## Simplest Callout

This example uses the following server configuration:

```conf
authorization:{
    users:[
        { user: auth, password: pwd }
    ]
    auth_callout:{
        # users mapped here, bypass the callout, any other users
        # will result in a request to the callout.
        auth_users:[auth]
        # in this type of configuration, the issuer for jwt.UserClaims
        # as well as the jwt.AuthorizationResponseClaim must be signed
        # with the private Account key matching the public key listed
        # as the issuer
        issuer: AAB35RZ7HJSICG7D4IGPYO3CTQPWWGULJXZYD45QAWUKTXJYDI6EO7MV
    }
}
```

To create a callout, you would connect to the NATS server using the `auth` user
and create a subscription to `$SYS.REQ.USER.AUTH`, and process the request as
above. You can examine the source in this project to see the nuances.

### The Callout Implementation

If you are using the callout library, the process is greatly simplified:

```go
// parse the private key
akp, _ := nkeys.FromSeed([]byte("SAAHZHKC43PG6B6EP3LZ7HB3HB3JD25GSJRV5LFZE2A6XFT57SDFRSEI4E"))

// a function that creates the users
authorizer := func(req *jwt.AuthorizationRequest) (string, error) {
	// peek at the req for information - for brevity
	// in the example, we simply allow them in
	
	// use the server specified user nkey
    uc := jwt.NewUserClaims(req.UserNkey)
	// put the user in the global account
    uc.Audience = "$G"
	// add whatever permissions you need
    uc.Sub.Allow.Add("_INBOX.>")
	// perhaps add an expiration to the JWT
    uc.Expires = time.Now().Unix() + 90
    return uc.Encode(akp)
}

// create a connection using the callout user
nc, _ := nats.Connect("nats://127.0.0.1", nats.UserInfo("auth", "pwd"))

// configure the authorization service with the connection, the function that 
// generates users, and the key to use to issue the jwt.AuthorizationResponseClaims
svc, err := NewAuthorizationService(serviceConn, Authorizer(authorizer), ResponseSignerKey(akp))
// done!
```

#### Adding Encryption

AuthorizatinRequests can be encrypted. Encrypting ensures that requests are
readable only to the owner of the specified encryption key, and that responses
are only readable to the server that sent the request.

Here's the same server configuration, but this time enabling encryption:

```conf
authorization:{
    users:[
        { user: auth, password: pwd }
    ]
    auth_callout:{
        auth_users:[auth]
        issuer: AAB35RZ7HJSICG7D4IGPYO3CTQPWWGULJXZYD45QAWUKTXJYDI6EO7MV
        # Specifying the public curve key, the server will send authorization
        # requests encrypted so that the public key specified can read them.
        # Likewise the server will expect the response to be encrypted on the
        # public key it specifies in the request.
        xkey: XBCW4J63ZDLH54GKXJLBJQOWXEWPIYXY23HBMWL5LX6U24FW3C6U2UUL
    }
}
```

On the callout side, the only additional requirement is to specify the option
`EncryptionKey`:

```go
xkey, _ := nkeys.CreateCurveKeys()
svc, err := NewAuthorizationService(serviceConn,
    Authorizer(authorizer), ResponseSignerKey(akp), EncryptionKey(xkey))
```

The library will ensure that both the server and service are using encryption,
and that the keys assets from the request are encrypted by the sending server,
and will encrypt the AuthorizationResponse.

### Delegated Authentication

Delegated Authentication increases the complixity a bit more. When using

A more complicated example using
[delegated authentication can be found here](examples/delegated/README.md).

### WebSocket

When using websockets, the `websocket` configuration on the server can specify

- `jwt_cookie` (only if using delegated auth), `user_cookie`, `pass_cookie`,
  `token_cookie`, these options specify the name of a cookie that is mapped to
  the connect option of the same name. Note that because of CORS, the cookies
  will have to be `Secure` and `SameSite` (`HttpOnly` is good too) (at least for
  browsers). This enables websockets on a browser to the connection options
  injected on HTTP server.

## More Examples TBD (look at the source Luke)

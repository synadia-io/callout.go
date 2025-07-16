#!/usr/bin/env bash
set -x

# put the nsc artifacts where we can find them
export TMPDIR=/tmp
export OUTDIR=$TMPDIR/DA
export XDG_CONFIG_HOME=$OUTDIR/config
export XDG_DATA_HOME=$OUTDIR/data


# add an operator
nsc add operator O
#nsc edit operator --account-jwt-server-url nats://localhost:4222
nsc export keys --operator --dir $OUTDIR
OPERATOR=$(nsc describe operator --json | jq .sub -r)
mv "$OUTDIR/$OPERATOR.nk" $OUTDIR/operator.nk

# add and register the system account
nsc add account SYS
nsc edit operator --system-account SYS
nsc add user --account SYS --name sys
nsc generate creds --account SYS --name sys -o $OUTDIR/sys.creds

# add the callout account
nsc add account C
# capture the ID (subject) for the callout account
CALLOUT=$(nsc describe account C --json | jq .sub -r)
cp "$XDG_DATA_HOME/nats/nsc/keys/keys/A/${CALLOUT:1:2}/${CALLOUT}.nk" $OUTDIR/C.nk
# add the service user, this user is for the callout service to connect to NATS
nsc add user service
SERVICE=$(nsc describe user service --json | jq .sub -r)
# add the sentinel users (no permissions) this is a callout user that will be given
# to all clients to authorize via the callout
nsc add user --account C --name sentinel --deny-pubsub \>
# the callout account needs to specify the ID of the service user, and the accounts
# that it can generate authorizations for
nsc edit authcallout --account C --auth-user $SERVICE --allowed-account "*"
# Export the JWT for account C
nsc describe account --raw -o $OUTDIR/C.jwt

# make a server configuration file
nsc generate config --nats-resolver --config-file /tmp/DA/server.conf
# extract the creds for the service and callout so we can use them
nsc generate creds --account C --name service -o $OUTDIR/service.creds
nsc generate creds --account C --name sentinel -o $OUTDIR/sentinel.creds
#Generate again as bearer so we can use it as default_sentinel
nsc edit user sentinel --bearer
nsc generate creds --account C --name sentinel -o $OUTDIR/sentinel_bearer.creds


mkdir -p $OUTDIR/jwt
nsc describe account C --raw > "$OUTDIR/jwt/$CALLOUT.jwt"



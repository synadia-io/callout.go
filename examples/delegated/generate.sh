#!/usr/bin/env bash
set -x

# put the nsc artifacts where we can find them
export TMPDIR=/tmp
export OUTDIR=$TMPDIR/DA
export XDG_CONFIG_HOME=$OUTDIR/config
export XDG_DATA_HOME=$OUTDIR/data

# add an operator
nsc add operator O

# add and register the system account
nsc add account SYS
nsc edit operator --system-account SYS

# add the account we are going to place users in via the callout
nsc add account A
# capture the ID (subject) for the account
ACCOUNT=$(nsc describe account A --json | jq .sub -r)

# add the callout account
nsc add account C
# capture the ID (subject) for the callout account
CALLOUT=$(nsc describe account C --json | jq .sub -r)
# add the service user, this user is for the callout service to connect to NATS
nsc add user service
SERVICE=$(nsc describe user service --json | jq .sub -r)
# add the sentinel users (no permissions) this is a callout user that will be given
# to all clients to authorize via the callout
nsc add user sentinel --deny-pubsub \>
# the callout account needs to specify the ID of the service user, and the accounts
# that it can generate authorizations for
nsc edit authcallout --account C --auth-user $SERVICE --allowed-account $ACCOUNT

# make a server configuration file
nsc generate config --mem-resolver --config-file /tmp/DA/server.conf
# extract the creds for the service and callout so we can use them
nsc generate creds --account C --name service -o $OUTDIR/service.creds
nsc generate creds --account C --name sentinel -o $OUTDIR/sentinel.creds
# need the callout account to sign the authorization responses
cp "$XDG_DATA_HOME/nats/nsc/keys/keys/A/${CALLOUT:1:2}/${CALLOUT}.nk" $OUTDIR/C.nk
# need the placement account for issuing users
cp "$XDG_DATA_HOME/nats/nsc/keys/keys/A/${ACCOUNT:1:2}/${ACCOUNT}.nk" $OUTDIR/A.nk




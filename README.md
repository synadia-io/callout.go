# Callout.go

[![Coverage Status](https://coveralls.io/repos/github/aricart/callout.go/badge.svg?branch=main)](https://coveralls.io/github/aricart/callout.go?branch=main)
[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/aricart/callout.go)](https://goreportcard.com/report/github.com/aricart/callout.go)


This library implements a small framework for writing AuthCallout services for NATS.

An AuthCallout is a service that generates an authorization for a user based on an 
external criteria. There are five aspects to a callout:

1. Receiving an authorization request
1. Decoding an authorization request
1. Generating a user JWT based on the authorization request information
1. Packaging an authorization response
1. Sending the authorization response to the server

With the exception of step #3, all the other operations are completely boilerplate. While
not complicated, it requires a careful understanding of the callout process and the features
it provides to make the callout process secure.

The callout library simply requires a custom function implementation for step #3 (generating
an user JWT), and handles all the other minutia automatically.

The library is implemented using the NATS services framework which enables you to easily
horizontally scale the service to meet your cluster's demand.
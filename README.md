# parsec

An experiment in [transaction tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) and generalizable trust architecture.

parsec is an implementation of [ext_authz](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3) and [token exchange](https://datatracker.ietf.org/doc/rfc8693/). It is intended to be used by the perimeter of a trust domain in order to:

- abstract away validating credentials from external trust domains (removing those credentials for services within the trust domain)
- issue trusted authorization context for a call chain (transaction token)

It is intended to be used as part of a general federated trust architecture that defines a (1) workload trust domain (expected to be abstracted in the network e.g. through a service mesh) and (2) a [potentially wider] transaction trust domain, established by this service as a transction token issuer.
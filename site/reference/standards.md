# Standards Scope

## Status

| Area                       | Status  | Notes                                                                                                       |
| -------------------------- | ------- | ----------------------------------------------------------------------------------------------------------- |
| RFC 5280 path validation   | partial | Core path validation, name constraints, policy processing, malformed-DER coverage, PKITS conformance subset |
| RFC 6960 OCSP              | partial | Request/response parsing, signature checks, responder authorization, nonce/freshness                        |
| RFC 6125 service identity  | partial | DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, opt-in CN-compat                                             |
| RFC 9618 policy validation | partial | Policy state, enforcement, outputs, focused PKITS coverage                                                  |

## What ships

### RFC 5280 path validation

- DER parsing strict enough to reject malformed certificates
- Issuer/subject chaining across candidate paths
- Signature verification using the evolving working public key
- Validity time checks (`notBefore` / `notAfter`)
- `basicConstraints` enforcement for CA certificates
- `pathLenConstraint` enforcement
- `keyUsage` enforcement (`keyCertSign` for CAs)
- Self-issued vs non-self-issued processing
- Supported-form name constraints (DNS, URI, email, IP)
- Critical extension rejection for unrecognized OIDs

### RFC 6960 OCSP

- Request creation with CertID (issuer hash + serial)
- Response parsing with status, certs, timestamps
- Signature verification
- Responder authorization (CA-signed, delegated with `ocspSigning` EKU)
- Nonce matching
- Freshness checks

### RFC 6125 service identity

- DNS-ID with single-level wildcard matching
- IP-ID with IPv6 normalization
- URI-ID scheme + host matching
- SRV-ID via otherName SAN
- IDNA-aware comparison
- Opt-in CN compatibility (disabled by default)

### RFC 9618 policy validation

- Policy state tracking across candidate paths
- Explicit policy enforcement
- Initial policy set validation

## What doesn't ship

- Full CRL distribution point processing
- Delta CRL support
- OCSP local responder-policy acceptance
- Broader PKITS conformance (ongoing)
- Certificate Policies extension parsing in chain validation
- Full name constraint processing for all GeneralName forms

For the authoritative scope boundary, see [`PKIX-SCOPE.md`](https://github.com/kjanat/ts-x509/blob/master/docs/PKIX-SCOPE.md).

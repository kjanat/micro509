# Standards Scope

## Status

| Area                       | Status   | Notes                                                                                                                                                                     |
| -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 5280 path validation   | complete | Full NIST PKITS suite passes (224 procedures, 249 runs; DSA chains expected-fail per the WebCrypto algorithm boundary); revocation is a separate API by design            |
| RFC 6960 OCSP              | complete | Full validation surface: parsing, signatures, responder authorization, revocation policy, nonce, freshness, chain orchestration; HTTP transport caller-provided by design |
| RFC 9525 service identity  | complete | Every identity type: DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, opt-in RFC 6125 CN-compat                                                                             |
| RFC 9618 policy validation | complete | Full PKITS policy sections (4.8–4.12, every documented subtest variation) pass                                                                                            |

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
- Name constraints: enforced for DNS, URI, email, IP, and directoryName;
  fail-closed for otherName / x400Address / ediPartyName / registeredID when
  a critical constraint meets a SAN of that form (RFC 5280 §4.2.1.10)
- Critical extension rejection for unrecognized OIDs

### RFC 6960 OCSP

- Request creation with CertID (issuer hash + serial)
- Response parsing with status, certs, timestamps
- Signature verification
- Responder authorization (CA-signed, delegated with `ocspSigning` EKU,
  locally trusted responders per RFC 6960 §4.2.2.2 criterion 1)
- Delegated responder revocation policy: `id-pkix-ocsp-nocheck`
  (`hasOcspNoCheckExtension()`), `honor-nocheck` / `require-evidence` /
  `skip` knobs with CRL evidence
- Historical-time responder chain validation (`at` flows through delegated
  chain checks)
- Nonce matching
- Freshness checks
- Chain-level orchestration: `checkChainRevocation()` /
  `verifyCertificateChain({ revocation })` consume caller-supplied OCSP
  responses alongside CRLs

### CRL processing

- Delta CRL merge
- Indirect issuer handling
- Scope matching
- Basic CRL parsing and revocation checks

::: tip Hard-fail default
Chain-level revocation checking runs only when evidence is supplied, and
then defaults to `mode: 'hard-fail'` — indeterminate status denies. Set
`mode: 'soft-fail'` explicitly to allow indeterminate results. See the
[revocation guide](/guide/revocation).
:::

### RFC 9525 service identity

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
- OCSP/CRL HTTP fetching (evidence is caller-provided by design)
- Semantic matching for otherName / x400Address / ediPartyName / registeredID
  name constraints (they fail closed instead when a critical constraint
  meets a name of that form)

For the authoritative scope boundary, see
[`PKIX-SCOPE.md`](https://github.com/kjanat/micro509/blob/master/docs/PKIX-SCOPE.md).

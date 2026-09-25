---
outline: [2, 3]
---

# Standards Scope

## Status

| Area                                        | Status   | Notes                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 5280 path validation                    | complete | Full NIST PKITS suite passes (224 procedures, 249 runs; DSA chains expected-fail per the WebCrypto algorithm boundary); revocation is a separate API by design                                                                                                                                                                                                             |
| RFC 6960 + 9919 OCSP                        | complete | Full validation surface: parsing, signatures, responder authorization, revocation policy, nonce, freshness, chain orchestration; CertID hashing defaults to SHA-256 per RFC 9919 §3.1.1 with explicit SHA-1 interop; opt-in RFC 9919 client profile rejects a response without `nextUpdate`, and the RFC 6960 default accepts it; HTTP transport caller-provided by design |
| RFC 9525 service identity                   | complete | Every identity type: DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, opt-in RFC 6125 CN-compat                                                                                                                                                                                                                                                                              |
| RFC 9618 policy validation                  | complete | Full PKITS policy sections (4.8–4.12, every documented subtest variation) pass                                                                                                                                                                                                                                                                                             |
| RFC 7468 PEM textual encodings              | complete | Strict generator/parser conformance backed by a section-complete executable suite; non-canonical base64 final quanta rejected per RFC 4648 §3.5; RFC 1421 folded encapsulated headers unfold for legacy traditional PEM                                                                                                                                                    |
| RFC 8410 + 9295 safe-curve profiles         | complete | Ed25519 end-to-end (keys, CSRs, certificates, signatures); Ed448/X25519/X448 parse with RFC 9295 §3 key-usage enforcement, their key operations outside the WebCrypto boundary; section-complete executable suite                                                                                                                                                          |
| PKCS containers: RFC 5652, 7292, 8018, 9879 | partial  | SignedData sign/parse/verify with signer resolution and cert bags (RFC 5652 subset); PFX create/parse with BER input and a SHA-256-only MAC (RFC 7292 subset); RFC 9879 PBMAC1 verification and opt-in creation; PBES2 with PBKDF2 HMAC-SHA-1/256 and AES-CBC (RFC 8018 subset); no enveloped/encrypted CMS content types                                                  |

## What ships

### RFC 5280 path validation

- DER encoding on output; parsing rejects malformed certificates and
  tolerates an explicitly encoded DEFAULT value (certificate version v1,
  `critical` FALSE, `cA` FALSE) as local policy per X.509 §7.2.1 NOTE 2
- BOOLEAN content other than a single `0x00` or `0xFF` octet rejected
- Issuer/subject chaining across candidate paths
- Signature verification using the evolving working public key
- Validity time checks (`notBefore` / `notAfter`)
- `basicConstraints` enforcement for CA certificates
- `pathLenConstraint` enforcement
- `keyUsage` enforcement (`keyCertSign` for CAs)
- Self-issued vs non-self-issued processing
- Name constraints: enforced for DNS, URI, email, IP, and directoryName;
  rfc822Name constraints also bind SmtpUTF8Mailbox SANs by domain (RFC 9598
  §6); fail-closed for otherName / x400Address / ediPartyName / registeredID
  when a critical constraint meets a SAN of that form (RFC 5280 §4.2.1.10)
- Critical extension rejection for unrecognized OIDs
- `noRevAvail` (RFC 9608): parsed, emitted by the builder, and a certificate
  pairing it with cA TRUE, cRLDistributionPoints, freshestCRL or an
  `id-ad-ocsp` location is rejected

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
- Freshness checks, with `clockSkewMs`
- Opt-in RFC 9919 client profile. `profile: 'rfc9919'` on
  `validateOcspResponse` (`ocspProfile: 'rfc9919'` on
  `checkCertificateRevocation` and the chain `RevocationPolicy`) rejects a
  response without `nextUpdate` (RFC 9919 §5). The default `'rfc6960'`
  profile accepts it (RFC 6960 §4.2.2.1)
- Chain-level orchestration: `checkChainRevocation()` /
  `verifyCertificateChain({ revocation })` consume caller-supplied OCSP
  responses alongside CRLs
- Chain-level revocation reports a certificate carrying `noRevAvail` or
  `id-pkix-ocsp-nocheck` as `skipped` without consulting evidence (RFC 9608
  §4)

### CRL processing

- Delta CRL merge using only a current delta whose CRL number exceeds its
  base's and preferring the latest `thisUpdate` (RFC 5280 §5.2.4), with a
  `thisUpdate` no earlier than the base's (X.509 Annex E.5.2)
- Generated CRLs always carry `nextUpdate` (RFC 5280 §5.1.2.5)
- Received CRLs without `nextUpdate` stay usable unless `maxAgeMs` /
  `crlMaxAgeMs` bounds the age of `thisUpdate` (RFC 5280 §3.3 local policy);
  unbounded by default
- Indirect issuer handling
- Scope matching
- Basic CRL parsing and revocation checks

::: tip Hard-fail default
Chain-level revocation checking runs only when evidence is supplied, and
then defaults to `mode: 'hard-fail'` — indeterminate status denies. Set
`mode: 'soft-fail'` explicitly to allow indeterminate results. See the
[revocation guide](/guide/revocation).
:::

### PKCS#12 (RFC 7292, RFC 9879)

- PFX create and parse, with BER accepted for the PFX, AuthenticatedSafe and
  SafeContents layers and DER required for certificate and key bags
- RFC 7292 MAC with SHA-256 only; the password must be a BMPString
- RFC 9879 PBMAC1 verification with PBKDF2 and HMAC-SHA-256/384/512, and
  opt-in creation with `mac: { type: 'pbmac1' }`
- KDF iteration budgets through `maxKdfIterations`; PBKDF2 counts are capped
  at 4294967295, the WebCrypto maximum

### RFC 9525 service identity

- DNS-ID with single-level wildcard matching
- IP-ID with IPv6 normalization
- URI-ID scheme + host matching
- SRV-ID via otherName SAN
- IDNA2008 reference conversion (RFC 5891 lookup, RFC 5895 mapping)
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

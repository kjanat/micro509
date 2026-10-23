# Migration guide

This guide covers upgrading from **0.14.x to 0.15.0**: certificate issuance,
CRL creation and freshness, OCSP responder trust, and revocation result types.

For the full change history, see the [changelog](https://github.com/kjanat/micro509/blob/master/CHANGELOG.md). The
[certificate guide](./getting-started.md), [revocation guide](./revocation.md),
and the generated API pages cover the current workflows.

## Supply the issuer certificate

`createCertificate` used to accept the issuer's public key as
`issuerPublicKey`. It now accepts the issuer certificate as `issuerCertificate`
(PEM, DER, or parsed certificate). The builder uses the certificate's subject
key identifier for the authority key identifier. If the issuer certificate
has no subject key identifier, micro509 derives one from its public key.

In 0.14.0, pass the issuer public key:

```ts
const leaf = await createCertificate({
  issuer: { commonName: 'Example CA' },
  subject: { commonName: 'service.example' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});
```

In 0.15.0, pass the issuer certificate:

```ts
const leaf = await createCertificate({
  issuer: { commonName: 'Example CA' },
  subject: { commonName: 'service.example' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerCertificate: ca.certificate.pem,
});
```

`issuerPublicKey` is no longer accepted. An issuer value that cannot be parsed
throws a `ResultError` with code `issuer_certificate_invalid`. Supplying the
certificate also aligns the authority key identifier with issuers whose
subject key identifier was not derived by the default method.

## Provide required CRL fields

`createCertificateRevocationList` now requires `issuerCertificate`,
`crlNumber`, and `nextUpdate`. It always writes the Authority Key Identifier,
CRL Number, and `nextUpdate` fields. `nextUpdate` must encode a time at least
one second after `thisUpdate` (which defaults to the current time).

In 0.14.0, the issuer public key, CRL number, and next update were optional:

```ts
const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Example CA' },
  signerPrivateKey: ca.keyPair.privateKey,
});
```

Version 0.15.0 requires the issuer certificate, CRL number, and next update:

```ts
const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Example CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerCertificate: ca.certificate.pem,
  crlNumber: 1n,
  thisUpdate: new Date(),
  nextUpdate: new Date(Date.now() + 24 * 60 * 60 * 1000),
});
```

If `nextUpdate` does not fall in a later second after both times are truncated
to whole seconds, the builder throws a `ResultError` with
code `next_update_not_after_this_update`. A CRL number that is negative,
non-integral, or larger than the permitted 20 encoded octets throws with code
`crl_number_invalid`. An invalid issuer certificate throws
`issuer_certificate_invalid`.

## Handle CRL numbers as `bigint`

The builder still accepts a `number` or `bigint` for `crlNumber` and
`baseCrlNumber`. Use `bigint` for parsed values and for numbers above
`Number.MAX_SAFE_INTEGER`. Parsed CRL fields now have type `bigint`, avoiding
loss of precision for valid CRL numbers up to 20 octets.

```ts
const parsed = parseCertificateRevocationListDerOrThrow(crl.der);
const number: bigint | undefined = parsed.crlNumber;

if (number !== undefined && number > 100n) {
  console.log('CRL is newer than number 100');
}
```

Code that previously compared a parsed CRL number to a numeric literal must
review the operation. Relational comparisons between `bigint` and `number` are
allowed, but equality comparisons and arithmetic have different type and
conversion rules. Use a bigint literal such as `100n` for equality and
arithmetic with a parsed CRL number. Convert to `number` only when the value is
within the safe integer range and an API requires a number.

## Handle unrecognized CRL reason codes

CRL reason codes outside the recognized values are no longer dropped. Parsed
reason values use `ParsedRevocationReason`: recognized values are strings,
while unknown values are represented as
`{ type: 'unrecognized', code: bigint }`. The code is `bigint` so values of any
length are represented exactly.

```ts
const reason = parsed.revokedCertificates[0]?.reasonCode;

if (reason !== undefined && typeof reason !== 'string') {
  console.log(`Unknown CRL reason: ${reason.code}`);
}
```

Consumers that display or switch on a reason must now handle the object
variant. The `unrecognizedReasonCode` option on CRL checks and chain revocation
policy controls how evidence with an unknown reason affects status. It defaults
to `'revoked'`. Choosing `'reject'` returns an unrecognized-reason error and prevents
other evidence from settling the status as good. A critical CRL reason with an
unrecognized value makes the CRL malformed.

## Handle OCSP reason codes as `bigint`

`revocationReasonCode` on a revoked `ParsedOcspCertStatus` and on the revoked
result from `checkCertificateRevocation` is now `bigint | undefined`.
`revocationReasonFromCode` also takes a `bigint`. Use `6n`, for example, when
comparing a parsed reason with `certificateHold`, and pass `6n` to
`revocationReasonFromCode`. The `createOcspResponse` builder still accepts
numeric reason codes such as `6`.

When serializing parsed CRL numbers or reason codes to JSON, convert those
fields to decimal strings with `.toString()`. `JSON.stringify` does not
serialize `bigint` values directly.

## Bind trusted OCSP responders to their issuer

`trustedOcspResponders` on `checkChainRevocation` and
`verifyCertificateChain({ revocation })` now takes `TrustedOcspResponder`
entries instead of bare responder certificates. Replace each responder value
with an object naming both its issuing-CA scope and the responder certificate:

```ts
const trustedOcspResponders = [
  {
    issuerCertificate: caCertificatePem,
    responderCertificate: responderCertificatePem,
  },
];
```

`issuerCertificate` identifies the CA whose certificates this responder may
report on. If a responder is trusted for several issuers, supply an entry for
each issuer. Trust for one CA no longer grants authority over every CA in the
validated path.

## Set an age policy for CRLs without `nextUpdate`

A received complete CRL without `nextUpdate` now fails with `stale_crl` unless
you supply a maximum age for its `thisUpdate`. Choose the age according to
your revocation policy, using the option for the API you call:

| API                                                                         | Option                                                       |
| --------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `validateCertificateRevocationList`, `checkCertificateRevocationAgainstCrl` | `maxAgeMs`                                                   |
| `checkCertificateRevocation`                                                | `crlMaxAgeMs`                                                |
| `checkChainRevocation`, `verifyCertificateChain`                            | `policy.crlMaxAgeMs`, `revocation.crlMaxAgeMs`, respectively |
| `validateOcspResponse` when checking a delegated responder's CRL            | `responderRevocationCrlMaxAgeMs`                             |

For example, `24 * 60 * 60 * 1000` bounds the age to one day. An expired
`nextUpdate` still fails even when an age bound is supplied. Delta CRLs must
have `nextUpdate`.

The chain-level age policy also applies to CRL signers and delegated OCSP
responders. Under the default hard-fail policy, a CRL without `nextUpdate` and
without an age bound cannot establish good status. Other applicable evidence
may still establish the certificate's status.

## Handle skipped revocation results

Chain revocation results now include `status: 'skipped'` for certificates
whose signed extensions exempt them from revocation checks. The `skipReason`
is `'no_rev_avail'` for `noRevAvail`, or `'ocsp_nocheck'` for
`id-pkix-ocsp-nocheck`.

Add this case to exhaustive switches over `result.value.certificates` from
`checkChainRevocation`. Display the exemption reason separately from a
validated `good` verdict. A skipped entry has no `source` or `revocationInfo`,
and no revocation evidence was consulted for that certificate.

## Update exhaustive type handling

`SubjectAltName` has additional typed variants, including `upn`,
`krb5PrincipalName` and `smtpUtf8Mailbox`. Code that previously handled these
values through generic `otherName` objects must handle their typed variants.
Review exhaustive switches over GeneralName values and error-code unions
when compiling against 0.15.0.

# Extensions

The built-in extensions (`basicConstraints`, `keyUsage`, SANs, …) encode and
decode automatically. This page covers the OIDs micro509 does not know:
embedding your own extension in a certificate, reading it back as a typed
value, and the `micro509/der` primitives both directions are built from.

## Embed a custom extension

`customExtensions` takes a pre-encoded DER payload for the extnValue.
`micro509/der` ships the builders to produce one without hand-assembling
bytes:

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import {
  derIntegerFromNumber,
  derSequence,
  derUtf8String,
  toHex,
} from 'micro509/der';
import {
  findExtension,
  parseCertificatePem,
} from 'micro509/x509';

// A private extension: SEQUENCE { tier UTF8String, seats INTEGER }
const LICENSE_OID = '1.3.6.1.4.1.55555.1';
const seats =
  crypto.getRandomValues(new Uint8Array(1))[0] ?? 25;
const payload = derSequence([
  derUtf8String('enterprise'),
  derIntegerFromNumber(seats),
]);

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'licensed.example' },
  extensions: {
    customExtensions: [
      { oid: LICENSE_OID, value: payload },
    ],
  },
});

const parsed = unwrap(parseCertificatePem(certificate.pem));
const raw = findExtension(parsed.extensions, LICENSE_OID);

console.log(`\
oid:      ${raw?.oid}
critical: ${raw?.critical}
payload:  ${toHex(payload)}
carried:  ${raw?.valueHex}`);
```

</LiveCode>

## Decode it back as a typed value

A `defineExtensionDecoder` registered through `ParseOptions` runs during
parsing and lands its typed result on the parsed certificate, next to the
built-in fields:

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import {
  decodeDerIntegerOrThrow,
  decodeDerStringOrThrow,
  derIntegerFromNumber,
  derSequence,
  derUtf8String,
  readDerSequenceOrThrow,
} from 'micro509/der';
import {
  defineExtensionDecoder,
  parseCertificatePem,
} from 'micro509/x509';

const LICENSE_OID = '1.3.6.1.4.1.55555.1';

const license = defineExtensionDecoder({
  oid: LICENSE_OID,
  decode(extension) {
    const [tier, seats] = readDerSequenceOrThrow(
      extension.valueDer,
    );
    if (tier === undefined || seats === undefined) {
      throw new Error('license needs tier and seats');
    }
    return {
      tier: decodeDerStringOrThrow(tier),
      seats: decodeDerIntegerOrThrow(seats),
    };
  },
});

// Same certificate shape as the previous example
const seats =
  crypto.getRandomValues(new Uint8Array(1))[0] ?? 25;
const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'licensed.example' },
  extensions: {
    customExtensions: [
      {
        oid: LICENSE_OID,
        value: derSequence([
          derUtf8String('enterprise'),
          derIntegerFromNumber(seats),
        ]),
      },
    ],
  },
});

const parsed = unwrap(
  parseCertificatePem(certificate.pem, {
    decoderMap: { license },
  }),
);

const decoded = parsed.decodedExtensionMap?.license;
console.log(`\
tier:  ${decoded?.value.tier}
seats: ${decoded?.value.seats}`);
```

</LiveCode>

A decoder that throws marks that extension undecoded instead of failing the
whole parse; the raw bytes stay reachable through `findExtension`. For a
one-off read without `ParseOptions`, `decodeExtension(parsed.extensions,
license)` applies a single decoder after the fact.

## Walk arbitrary DER

The readers work on any DER, not only extension payloads. Every reader has
two forms. The plain form returns a typed `Result` and `OrThrow` throws, the same split
as the rest of the library.

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  decodeDerOidOrThrow,
  derChildrenOrThrow,
  readDerRootOrThrow,
  toHex,
} from 'micro509/der';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'walk.example' },
});

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
const root = readDerRootOrThrow(certificate.der);
const [tbs, sigAlg, sig] = derChildrenOrThrow(
  certificate.der,
  root,
);
if (
  tbs === undefined ||
  sigAlg === undefined ||
  sig === undefined
) {
  throw new Error('expected three certificate fields');
}

// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, ... }
const [algorithm] = derChildrenOrThrow(
  certificate.der,
  sigAlg,
);
if (algorithm === undefined) {
  throw new Error('empty AlgorithmIdentifier');
}

console.log(`\
tbs:       tag 0x${tbs.tag.toString(16)}, ${tbs.value.length} bytes
sig algo:  ${decodeDerOidOrThrow(algorithm)}
signature: ${toHex(sig.value).slice(0, 48)}…`);
```

</LiveCode>

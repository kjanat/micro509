# Keys

## Generate a key pair

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';

// Ed25519
const ed = await generateKeyPair({ kind: 'ed25519' });

// ECDSA P-256
const ec = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// RSA 2048
const rsa = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});

console.log(
  'generated:',
  ed.publicKey.algorithm.name,
  ec.publicKey.algorithm.name,
  rsa.publicKey.algorithm.name,
);
```

</LiveCode>

## Import and export

### PKCS#8 (private keys)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPkcs8Pem,
  importPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportPkcs8Pem(keys.privateKey);

const privateKey = unwrap(
  await importPkcs8Pem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportPkcs8Pem(privateKey);

console.log('pkcs8 round-trip ok:', exported === pem);
```

</LiveCode>

### SPKI (public keys)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportSpkiPem,
  importSpkiPem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSpkiPem(keys.publicKey);

const publicKey = unwrap(
  await importSpkiPem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportSpkiPem(publicKey);

console.log('spki round-trip ok:', exported === pem);
```

</LiveCode>

The algorithm argument is optional for SPKI imports. A SubjectPublicKeyInfo
already encodes its algorithm OID (and, for EC keys, the curve), so
`importSpkiPem`, `importSpkiDer`, and `importSpkiBase64` infer it when no hint
is given — handy when the key type isn't known ahead of time:

```ts
// Inferred from the DER — no { kind, curve } needed.
const publicKey = unwrap(await importSpkiPem(pem));
```

Passing an explicit algorithm still works and additionally asserts that the key
matches it, failing with a `'malformed'` result on a mismatch.

### Derive a public key from a private key

The `import*` functions for private keys hand back a bare `CryptoKey` with only
`sign` usage — there is no matching public handle. `derivePublicKey` bridges
that gap, so a private key loaded from disk can go straight to
`exportSpkiPem`/`exportSpkiDer` (e.g. to rebuild a self-signed certificate or
distribute the public key). It supports RSA, ECDSA, and Ed25519.

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  derivePublicKey,
  exportSpkiPem,
  importPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// Start from a private key that carries no public handle.
const privateKey = unwrap(
  await importPkcs8Pem(await keys.exportPkcs8Pem(), {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);

const publicKey = await derivePublicKey(privateKey);
const spki = await exportSpkiPem(publicKey);

console.log(
  'derived spki matches:',
  spki === (await keys.exportSpkiPem()),
);
```

</LiveCode>

### JWK

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPrivateJwk,
  exportPublicJwk,
  importPrivateJwk,
  importPublicJwk,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pubJwk = await exportPublicJwk(keys.publicKey);
const privJwk = await exportPrivateJwk(keys.privateKey);

const publicKey = unwrap(
  await importPublicJwk(pubJwk, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const privateKey = unwrap(
  await importPrivateJwk(privJwk, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);

console.log(
  'jwk round-trip:',
  publicKey.type,
  privateKey.type,
);
```

</LiveCode>

### PKCS#1 (RSA-specific)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPkcs1Pem,
  importPkcs1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});
const pem = await exportPkcs1Pem(keys.privateKey);

const privateKey = unwrap(
  await importPkcs1Pem(pem, {
    kind: 'rsa',
    scheme: 'pkcs1-v1_5',
  }),
);
const exported = await exportPkcs1Pem(privateKey);

console.log('pkcs1 round-trip ok:', exported === pem);
```

</LiveCode>

### SEC1 (EC-specific)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportSec1Pem,
  importSec1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSec1Pem(keys.privateKey);

const privateKey = unwrap(
  await importSec1Pem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportSec1Pem(privateKey);

console.log('sec1 round-trip ok:', exported === pem);
```

</LiveCode>

## Encrypted keys

### Encrypted PKCS#8

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import {
  exportEncryptedPkcs8Pem,
  importEncryptedPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// Export with PBES2 encryption
const pem = await exportEncryptedPkcs8Pem(keys.privateKey, {
  password: 'password',
});

// Import with the same password — returns a Result
const result = await importEncryptedPkcs8Pem(
  pem,
  'password',
  {
    kind: 'ecdsa',
    curve: 'P-256',
  },
);

if (!result.ok) {
  // result.error.code is 'invalid_password' on a wrong password,
  // or 'malformed' on structurally invalid input
  throw new Error(result.error.code);
}

console.log('encrypted pkcs8 imported:', result.value.type);
```

</LiveCode>

### Legacy encrypted PEM (OpenSSL format)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportEncryptedPkcs1Pem,
  importEncryptedPkcs1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});

// Export RSA key with AES-256-CBC
const pem = await exportEncryptedPkcs1Pem(keys.privateKey, {
  password: 'password',
  cipher: 'AES-256-CBC',
});

// Import with the same password
const privateKey = unwrap(
  await importEncryptedPkcs1Pem(pem, 'password', {
    kind: 'rsa',
    scheme: 'pkcs1-v1_5',
  }),
);

console.log('encrypted pkcs1 imported:', privateKey.type);
```

</LiveCode>

## RSA-OAEP encryption

Generate or import RSA keys with `scheme: 'oaep'` to get an encryption pair
(`encrypt`/`decrypt` usages instead of `sign`/`verify`), then use
`encryptRsaOaep` / `decryptRsaOaep`. RSA-OAEP fits at most
modulus bytes − 2 × hash bytes − 2 per call (190 bytes for RSA-2048 with
SHA-256) — encrypt a symmetric key, not bulk data.

An optional `label` is bound to the ciphertext: decryption fails unless the
exact same label is presented. Decryption failures are deliberately opaque
(`decryption_failed`) — OAEP does not reveal whether the key, label, or
ciphertext was wrong.

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  decryptRsaOaep,
  encryptRsaOaep,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  scheme: 'oaep',
  modulusLength: 2048,
});

const label = new TextEncoder().encode('context-v1');
const ciphertext = unwrap(
  await encryptRsaOaep(
    keys.publicKey,
    new TextEncoder().encode('session key'),
    { label },
  ),
);

const plaintext = unwrap(
  await decryptRsaOaep(keys.privateKey, ciphertext, {
    label,
  }),
);

// Wrong label: opaque failure, never a partial plaintext
const wrongLabel = await decryptRsaOaep(
  keys.privateKey,
  ciphertext,
);

console.log(
  'roundtrip:',
  new TextDecoder().decode(plaintext),
  '| wrong label code:',
  wrongLabel.ok ? 'unexpected' : wrongLabel.code,
);
```

</LiveCode>

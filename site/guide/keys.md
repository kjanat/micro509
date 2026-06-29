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
import { generateKeyPair } from 'micro509';
import {
  exportPkcs8Pem,
  importPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportPkcs8Pem(keys.privateKey);

const privateKey = await importPkcs8Pem(pem, {
  kind: 'ecdsa',
  curve: 'P-256',
});
const exported = await exportPkcs8Pem(privateKey);

console.log('pkcs8 round-trip ok:', exported === pem);
```

</LiveCode>

### SPKI (public keys)

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import {
  exportSpkiPem,
  importSpkiPem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSpkiPem(keys.publicKey);

const publicKey = await importSpkiPem(pem, {
  kind: 'ecdsa',
  curve: 'P-256',
});
const exported = await exportSpkiPem(publicKey);

console.log('spki round-trip ok:', exported === pem);
```

</LiveCode>

### JWK

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
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

const publicKey = await importPublicJwk(pubJwk, {
  kind: 'ecdsa',
  curve: 'P-256',
});
const privateKey = await importPrivateJwk(privJwk, {
  kind: 'ecdsa',
  curve: 'P-256',
});

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
import { generateKeyPair } from 'micro509';
import {
  exportPkcs1Pem,
  importPkcs1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});
const pem = await exportPkcs1Pem(keys.privateKey);

const privateKey = await importPkcs1Pem(pem, {
  kind: 'rsa',
  scheme: 'pkcs1-v1_5',
});
const exported = await exportPkcs1Pem(privateKey);

console.log('pkcs1 round-trip ok:', exported === pem);
```

</LiveCode>

### SEC1 (EC-specific)

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import {
  exportSec1Pem,
  importSec1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSec1Pem(keys.privateKey);

const privateKey = await importSec1Pem(pem, {
  kind: 'ecdsa',
  curve: 'P-256',
});
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

// Import with the same password
const privateKey = await importEncryptedPkcs8Pem(
  pem,
  'password',
  {
    kind: 'ecdsa',
    curve: 'P-256',
  },
);

console.log('encrypted pkcs8 imported:', privateKey.type);
```

</LiveCode>

### Legacy encrypted PEM (OpenSSL format)

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
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
const privateKey = await importEncryptedPkcs1Pem(
  pem,
  'password',
  {
    kind: 'rsa',
    scheme: 'pkcs1-v1_5',
  },
);

console.log('encrypted pkcs1 imported:', privateKey.type);
```

</LiveCode>

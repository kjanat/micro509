# Keys

## Generate a key pair

```ts
import { generateKeyPair } from 'micro509';

// Ed25519
const ed = await generateKeyPair({ kind: 'ed25519' });

// ECDSA P-256
const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });

// RSA 2048
const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
```

## Import and export

### PKCS#8 (private keys)

```ts
import { importPkcs8Pem, exportPkcs8Pem } from 'micro509/keys';

const privateKey = await importPkcs8Pem(pem, { kind: 'ecdsa', curve: 'P-256' });
const exported = await exportPkcs8Pem(privateKey);
```

### SPKI (public keys)

```ts
import { importSpkiPem, exportSpkiPem } from 'micro509/keys';

const publicKey = await importSpkiPem(pem, { kind: 'ecdsa', curve: 'P-256' });
const exported = await exportSpkiPem(publicKey);
```

### JWK

```ts
import { importPublicJwk, importPrivateJwk } from 'micro509/keys';

const publicKey = await importPublicJwk(jwk, { kind: 'ecdsa', curve: 'P-256' });
const privateKey = await importPrivateJwk(jwk, { kind: 'ecdsa', curve: 'P-256' });
```

### PKCS#1 (RSA-specific)

```ts
import { importPkcs1Pem, exportPkcs1Pem } from 'micro509/keys';

const privateKey = await importPkcs1Pem(pem, { kind: 'rsa', scheme: 'pkcs1-v1_5' });
const exported = await exportPkcs1Pem(privateKey);
```

### SEC1 (EC-specific)

```ts
import { importSec1Pem, exportSec1Pem } from 'micro509/keys';

const privateKey = await importSec1Pem(pem, { kind: 'ecdsa', curve: 'P-256' });
const exported = await exportSec1Pem(privateKey);
```

## Encrypted keys

### Encrypted PKCS#8

```ts
import { importEncryptedPkcs8Pem, exportEncryptedPkcs8Pem } from 'micro509/keys';

// Import
const privateKey = await importEncryptedPkcs8Pem(pem, 'password', {
  kind: 'ecdsa',
  curve: 'P-256',
});

// Export with PBES2 encryption
const encrypted = await exportEncryptedPkcs8Pem(privateKey, 'password');
```

### Legacy encrypted PEM (OpenSSL format)

```ts
import { importEncryptedPkcs1Pem, exportEncryptedPkcs1Pem } from 'micro509/keys';

// RSA private key with AES-256-CBC
const privateKey = await importEncryptedPkcs1Pem(pem, 'password', {
  kind: 'rsa',
  scheme: 'pkcs1-v1_5',
});

const encrypted = await exportEncryptedPkcs1Pem(privateKey, 'password', {
  cipher: 'aes-256-cbc',
});
```

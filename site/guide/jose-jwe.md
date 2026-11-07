---
sidebarTitle: Encrypted JWE payloads
outline: [2, 3]
---

# Encrypt and decrypt compact JWE

`encryptCompactJwe` and `decryptCompactJwe` return `JoseResult`. The supported
profile is `RSA-OAEP-512` key management plus `A256GCM` content encryption. It fits
a small encrypted authorization-state payload without building a second JOSE
implementation around RSA and AES primitives. It adds no runtime dependency.

## Encrypt bytes with an explicitly bound key

Generate or import an RSA-OAEP key with **SHA-512**. A generic `rsaEncryption`
PKCS#8/SPKI envelope does not encode the OAEP hash; pass
`{ kind: 'rsa', scheme: 'oaep', hash: 'SHA-512' }` to the key importer.
A signing key or an OAEP/SHA-256 key is unsuitable even if its modulus matches.

<LiveCode>

```ts
import {
  generateKeyPair,
  importPrivateKeyPem,
  importSpkiPem,
} from 'micro509/keys';
import { encryptCompactJwe, decryptCompactJwe } from 'micro509/jose';
import { unwrap } from 'micro509/result';

const descriptor = { kind: 'rsa', scheme: 'oaep', hash: 'SHA-512' } as const;
const pair = await generateKeyPair(descriptor);
const publicKey = unwrap(
  await importSpkiPem(await pair.exportSpkiPem(), descriptor),
);
const privateKey = unwrap(
  await importPrivateKeyPem(await pair.exportPkcs8Pem(), descriptor),
);
const plaintext = new TextEncoder().encode(
  JSON.stringify({ state: 'café 🦊' }),
);
const token = unwrap(
  await encryptCompactJwe({
    publicKey,
    plaintext,
    algorithm: 'RSA-OAEP-512',
    encryption: 'A256GCM',
    header: { typ: 'state+jwe', kid: 'state-1' },
  }),
);
const decrypted = unwrap(
  await decryptCompactJwe(token, {
    privateKey,
    keyManagementAlgorithms: ['RSA-OAEP-512'],
    contentEncryptionAlgorithms: ['A256GCM'],
  }),
);
if (
  new TextDecoder().decode(decrypted.plaintext) !==
  new TextDecoder().decode(plaintext)
) {
  throw new Error('plaintext mismatch');
}
console.log('Compact JWE:', token);
console.log('Decrypted bytes:', new TextDecoder().decode(decrypted.plaintext));
```

</LiveCode>

No `typ` is inserted automatically. Decryption retains protected members;
applications must check their expected `typ`, payload schema, expiry and replay
policy before using the state. Encryption provides confidentiality and GCM
integrity, **not sender identity**: anyone with the public key can encrypt.
Signed nested JWTs need a separate explicit verification step after decryption.

## Wire format and failure policy

The five segments are protected header, RSA-encrypted CEK, IV, ciphertext and
authentication tag. The original encoded header segment is ASCII AAD, never a
reserialized JSON object. A new random 32-byte CEK and 12-byte IV are generated
per encryption, with a 16-byte tag. These APIs expose no IV reuse knob.

Both decryption allowlists are required. Malformed encoding/header, disallowed
`alg`/`enc`, and unsuitable CryptoKeys have distinct codes. RSA unwrap, incorrect
unwrapped CEK length, wrong private key and tag failure all return
`decryption_failed` with the same message. Failed unwrap continues using a
random replacement CEK and attempts GCM authentication, following RFC 7516
§11.5's mitigation; this does not promise constant timing in JavaScript.
Wrong RSA ciphertext length is rejected before RSA, following that same dummy
CEK path. Wrong IV/tag size is rejected before cryptographic operations.

The profile refuses compression (`zip`) and all critical extensions (`crit`),
rejects duplicate JSON members, and retains unknown noncritical headers.
RSA moduli must be 2048–8192 bits. Defaults bound compact tokens to 32,768
characters, headers to 4,096 bytes and plaintext/ciphertext to 16,384 bytes.
`limits.maxSignatureBytes` bounds the encrypted CEK (default 1,024 bytes);
JSON depth/node limits also apply. No decompression, JSON serialization,
multiple recipients, external AAD or other JWE algorithms are implemented.

Primary definitions: [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html),
[A256GCM](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3) and the
[IANA JOSE algorithm registry](https://www.iana.org/assignments/jose/jose.xhtml).

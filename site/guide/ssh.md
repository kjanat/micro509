---
sidebarTitle: SSH keys
outline: [2, 3]
---

# Import, convert and export SSH keys

Use `micro509/ssh` to read OpenSSH key material into WebCrypto `CryptoKey`s,
convert it to PEM formats, and write OpenSSH keys again. RSA, Ed25519 and
ECDSA P-256/P-384/P-521 are supported.

The examples below all use the same Ed25519 demo key. Its public line, private
file and SPKI are included so each example runs independently and their
fingerprints can be compared. This key is published demo material.

## Inspect a public key

Pass the contents of a `.pub` file to `importSshPublicKey`. The result includes
the comment, algorithm, public `CryptoKey` and OpenSSH-style SHA-256 fingerprint.
For an existing file, read its text in your application and replace `publicLine`.

<LiveCode data-output="deterministic">

```ts
import { exportSpkiPem } from 'micro509/keys';
import { importSshPublicKey } from 'micro509/ssh';

const publicLine =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEe8pyyvj5Dmkk+3GLdlRTCy23tkJN+qAoA277AqkMTa docs@example.com';
const result = await importSshPublicKey(publicLine);
if (!result.ok) throw new Error(result.error.code);

console.log('Public line:', publicLine);
console.log('Key type:', result.value.keyType);
console.log('Comment:', result.value.comment);
console.log('Fingerprint:', result.value.fingerprint);
console.log('SPKI PEM:', await exportSpkiPem(result.value.publicKey));
```

</LiveCode>

Save the printed public line as `demo.pub`. OpenSSH should print the same
fingerprint:

```bash
ssh-keygen -lf demo.pub -E sha256
```

For this key, the fingerprint is `SHA256:h4TPQn6XDJNXs9cPaExw1sEckQM+SWlkc3GdYQfyRLA`.
The fingerprint identifies the SSH public-key blob, so converting the key to
SPKI and back produces the same fingerprint. Hashing the SPKI bytes directly
would hash a different encoding.

## Import and convert a private key

`importOpenSshPrivateKey` accepts an **unencrypted, single-key** OpenSSH private
file as text or bytes. Password-protected files return `unsupported`.

This example imports the demo private key, converts it to PKCS#8, and exports
it as an OpenSSH private file again. It also prints the corresponding public
line and fingerprint for comparison with the first example.

<LiveCode>

```ts
import { exportPkcs8Pem } from 'micro509/keys';
import {
  exportOpenSshPrivateKey,
  exportSshPublicKey,
  importOpenSshPrivateKey,
} from 'micro509/ssh';

const privateFile = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACBHvKcsr4+Q5pJPtxi3ZUUwstt7ZCTfqgKANu+wKpDE2gAA
AJjG4ObKxuDmygAAAAtzc2gtZWQyNTUxOQAAACBHvKcsr4+Q5pJPtxi3ZUUwstt7
ZCTfqgKANu+wKpDE2gAAAECqFGHsHLN5lRCCAPIxD/kHFhY1mlExMyCLZ9zGqUvE
H0e8pyyvj5Dmkk+3GLdlRTCy23tkJN+qAoA277AqkMTaAAAAEGRvY3NAZXhhbXBs
ZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`;
const result = await importOpenSshPrivateKey(privateFile);
if (!result.ok) throw new Error(result.error.code);
const imported = result.value;

console.log('Fingerprint:', imported.fingerprint);
console.log(
  'Public line:',
  await exportSshPublicKey(imported.publicKey, {
    comment: imported.comment,
  }),
);
console.log('PKCS#8 private key:', await exportPkcs8Pem(imported.privateKey));
console.log(
  'OpenSSH private key:',
  await exportOpenSshPrivateKey(imported.privateKey, {
    comment: imported.comment,
  }),
);
```

</LiveCode>

The imported private key has `sign` usage and its public key has `verify` usage.
Both are extractable. Use the [Keys guide](./keys.md#import-and-export) for
PKCS#8, SPKI and JWK conversions, or [encrypted PKCS#8](./keys.md#encrypted-pkcs8)
to produce a password-protected private-key container.

OpenSSH private exports include random check integers. Two exported files can
differ while holding the same key. Compare their public keys or fingerprints.

## Export a public key to OpenSSH

Here is the SPKI printed by the first example. Importing it and calling
`exportSshPublicKey` produces the original `.pub` line. The comment is metadata
you supply separately from the key.

<LiveCode data-output="deterministic">

```ts
import { importSpkiPemOrThrow } from 'micro509/keys';
import { exportSshPublicKey, sshFingerprintSha256 } from 'micro509/ssh';

const spki = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAR7ynLK+PkOaST7cYt2VFMLLbe2Qk36oCgDbvsCqQxNo=
-----END PUBLIC KEY-----`;
const publicKey = await importSpkiPemOrThrow(spki);
console.log(
  await exportSshPublicKey(publicKey, { comment: 'docs@example.com' }),
);
console.log('Fingerprint:', await sshFingerprintSha256(publicKey));
```

</LiveCode>

Export requires an extractable key. `exportSshPublicKey` and
`exportOpenSshPrivateKey` throw a typed `ResultError` for `not_extractable`,
`unsupported_algorithm`, `invalid_key` or `invalid_comment`. See
[handling builder errors](../reference/errors.md) for `isResultError`.

## Handle import failures

Imports return a result. Branch on `result.error.code` when accepting uploaded
or pasted key material:

| Code              | Meaning and response                                                                                             |
| ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `malformed`       | The file or key encoding is invalid. Ask for the complete, original key file.                                    |
| `unsupported`     | The key type, encryption or container is outside the accepted formats, or an RSA key is below your minimum size. |
| `key_mismatch`    | A private file's embedded public and private keys disagree. Reject it.                                           |
| `limit_exceeded`  | The file or key exceeds the size limits below.                                                                   |
| `invalid_options` | Fix the import options supplied by your application.                                                             |

The complete result and error types are in the [SSH API reference](../api/ssh.md).

## Formats and import options

| Input        | Supported                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------- |
| Public line  | `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` |
| Private file | `OPENSSH PRIVATE KEY`, `openssh-key-v1`, one key, cipher and KDF both `none`                  |

Encrypted OpenSSH files, SSH certificates, `authorized_keys` options, `sk-*`
keys and DSA are unsupported. This module converts key material. SSH connections
and protocol authentication belong to an SSH client.

| Import option              | Default               | When to change it                                                                    |
| -------------------------- | --------------------- | ------------------------------------------------------------------------------------ |
| `minRsaModulusBits`        | `2048`                | Your application's RSA key-size policy differs.                                      |
| `acceptCompressedEcPoints` | `false`               | You need to read compressed ECDSA points permitted by RFC 5656.                      |
| `rsa.scheme` / `rsa.hash`  | PKCS#1 v1.5 / SHA-256 | The imported RSA `CryptoKey` will be used with a different signature scheme or hash. |

The `ssh-rsa` label describes a key encoding. It does not select SHA-1 signatures.
RSA-SHA2 signature algorithms also use that encoding. The `rsa` import options
select the WebCrypto signature parameters.

Public lines are limited to 16 KiB, private files to 32 KiB, and RSA moduli to
16384 bits. Comments allow at most 8192 UTF-8 bytes and must be well-formed
Unicode without CR, LF or NUL.

<details>
<summary>Private-key consistency and buffer handling</summary>

Imports check that the private section describes the file's public key and that
a signature from the private key verifies under it. RSA imports also check the
relationships between the modulus, prime factors, exponents and CRT coefficient.
Ed25519's embedded public-key bytes must agree with the public key.

The decoded private-file buffer is zeroed before import returns. Export zeroes
its combined private-field, padded-section and file buffers. Strings and temporary
field encodings are managed by JavaScript and cannot all be erased explicitly.

</details>

Continue with [key conversions](./keys.md), the [SSH API](../api/ssh.md),
or the [SSH error codes](../reference/errors.md#ssherrorcode).

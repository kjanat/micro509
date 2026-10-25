---
outline: [2, 3]
---

# SSH keys

`micro509/ssh` converts OpenSSH key files to WebCrypto keys and back. It reads
and writes public-key lines (`.pub` files), unencrypted `openssh-key-v1` private
keys, and `SHA256:` fingerprints for RSA, Ed25519, and ECDSA on P-256, P-384 and
P-521. It opens no connection and imports nothing from the certificate modules.

## Import a private key

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportOpenSshPrivateKey,
  exportSshPublicKey,
  importOpenSshPrivateKey,
} from 'micro509/ssh';

const keys = await generateKeyPair({ kind: 'ed25519' });
const file = await exportOpenSshPrivateKey(keys.privateKey, {
  comment: 'me@host',
});

const imported = unwrap(await importOpenSshPrivateKey(file));
const line = await exportSshPublicKey(imported.publicKey, {
  comment: imported.comment,
});

console.log(`\
type:        ${imported.keyType}
comment:     ${imported.comment}
fingerprint: ${imported.fingerprint}
public line: ${line}`);
```

</LiveCode>

`importOpenSshPrivateKey` takes the PEM file as text or bytes and returns the
`privateKey` (`sign`), the `publicKey` (`verify`), the comment, and the
fingerprint. Both keys are extractable, so `exportPkcs8Pem`, `exportSpkiPem`,
`exportPrivateJwk` and the other `micro509/keys` exports work on them.

<LiveCode data-output="deterministic">

```ts
import { importSshPublicKey } from 'micro509/ssh';

const result = await importSshPublicKey(
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host',
);
console.log(result);
```

</LiveCode>

## Accepted formats

| Input            | Accepted                                                                                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| Public-key line  | `<type> <base64> [comment]` with `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521` |
| Private-key file | `-----BEGIN OPENSSH PRIVATE KEY-----` holding one key, cipher `none`, KDF `none`                           |
| Not accepted     | encrypted files, files with several keys, `authorized_keys` options, SSH certificates, `sk-*` keys, DSA    |

Encrypted files and multi-key files return `unsupported`. Strict parsing
rejects a bad magic header, truncated or oversize fields, non-canonical or
negative `mpint`s, differing check integers, wrong padding, and trailing bytes.

### The `ssh-rsa` name

`ssh-rsa` names the RSA public-key encoding. [RFC 8332][rfc8332] reuses that
encoding for the `rsa-sha2-256` and `rsa-sha2-512` signature algorithms, so
importing an `ssh-rsa` key enables no SHA-1 signature. The `rsa` option picks how
the returned `CryptoKey` signs, PKCS#1 v1.5 with SHA-256 by default.

## Consistency checks

An embedded public key must match its private key. A mismatch returns
`key_mismatch`:

- the private section's key type and public key equal the file's public key.
- RSA: `p·q = n`, `d·e ≡ 1` modulo `p-1` and `q-1`, and `iqmp·q ≡ 1 (mod p)`.
- Ed25519: the 64-byte private field ends with the public key.
- every key type: a signature made with the private key verifies under the
  embedded public key.

## Policy options

The standards leave these choices to the relying party:

| Option                     | Default | Effect                                                               |
| -------------------------- | ------- | -------------------------------------------------------------------- |
| `minRsaModulusBits`        | `2048`  | smaller RSA keys return `unsupported`. OpenSSH itself accepts 1024   |
| `acceptCompressedEcPoints` | `false` | read SEC 1 compressed ECDSA points, which [RFC 5656][rfc5656] allows |

Limits are fixed: 16 KiB for a public-key line, 32 KiB for a private file, and
RSA moduli up to 16384 bits (`limit_exceeded`). Comments are limited to 8192
UTF-8 bytes and must be well-formed Unicode without CR, LF or NUL. A leading
Unicode BOM in a comment is preserved. Invalid policy options return
`invalid_options`.

## Fingerprints

`sshFingerprintSha256` returns the value `ssh-keygen -l -E sha256` prints: the
SHA-256 digest of the SSH public-key blob, base64 without padding, prefixed with
`SHA256:`. It is not a certificate fingerprint and not a digest of the SPKI.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import { sshFingerprintSha256 } from 'micro509/ssh';

const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
console.log(await sshFingerprintSha256(keys.publicKey));
```

</LiveCode>

## Export

`exportSshPublicKey` and `exportOpenSshPrivateKey` need extractable keys and
throw a `ResultError` with a code of `invalid_key`, `unsupported_algorithm`,
`not_extractable` or `invalid_comment`. The check integers in a private file
are random and differ between exports, so compare keys rather than file bytes. `ssh-keygen`
reads the exported file as is.

## Secret handling

Your input buffers are never modified. The decoded binary copy of a private file
is zeroed before import returns. Export zeroes its combined private-field,
padded-section and file buffers. Temporary field encodings are garbage-collected.
PEM text, base64 strings and JWK member strings cannot be zeroed. Error messages
contain no key material.

[rfc8332]: https://www.rfc-editor.org/rfc/rfc8332.html#section-3
[rfc5656]: https://www.rfc-editor.org/rfc/rfc5656.html#section-3.1

# Verification

## Chain verification

```ts
import { verifyCertificateChain } from 'micro509';

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'serverAuth',
  serviceIdentity: {
    type: 'dns',
    value: 'api.example.com',
  },
});

if (result.ok) {
  console.log(
    'Valid chain:',
    result.value.chain.length,
    'certificates',
  );
} else {
  console.log('Failed:', result.error.code);
  console.log('At index:', result.error.index);
}
```

## Verification purposes

Four built-in validation profiles:

```ts
// TLS server (default)
await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'serverAuth',
});

// TLS client
await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'clientAuth',
});

// Code signing
await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'codeSigning',
});

// CA certificate
await verifyCertificateChain({
  leaf: intermediate.pem,
  roots: [root.pem],
  purpose: 'ca',
});
```

## Service identity matching

```ts
import { matchServiceIdentity } from 'micro509/verify';

const result = matchServiceIdentity({
  certificate: parsed,
  identity: { type: 'dns', value: 'example.com' },
});

if (!result.ok) {
  console.log(result.error.code);
  // 'san_mismatch' | 'no_san_extension' | ...
}
```

Supported identity types:

- **DNS-ID** — with wildcard matching and case-insensitive comparison
- **IP-ID** — with IPv6 normalization
- **URI-ID** — scheme + host matching
- **SRV-ID** — service name matching via otherName SAN

## Error codes

The `VerifyErrorCode` type covers 21 failure modes:

| Code                                         | Meaning                                      |
| -------------------------------------------- | -------------------------------------------- |
| `no_trusted_root`                            | No trust anchor matched the chain            |
| `issuer_not_found`                           | Could not find issuer for a certificate      |
| `signature_invalid`                          | Cryptographic signature check failed         |
| `certificate_expired`                        | Certificate outside validity window          |
| `ca_required`                                | Non-CA certificate used as issuer            |
| `key_cert_sign_required`                     | Issuer missing `keyCertSign` key usage       |
| `path_length_exceeded`                       | Chain exceeds `pathLenConstraint`            |
| `authority_key_identifier_mismatch`          | AKI/SKI cross-check failed                   |
| `extended_key_usage_invalid`                 | EKU doesn't match requested purpose          |
| `subject_alt_name_mismatch`                  | SAN doesn't match service identity           |
| `common_name_fallback_suppressed`            | CN match suppressed by presented identifiers |
| `self_signed_leaf_not_allowed`               | Self-signed leaf without explicit opt-in     |
| `unrecognized_critical_extension`            | Unknown critical extension                   |
| `intermediate_eku_constraint`                | Intermediate has restrictive EKU             |
| `policy_processing_not_implemented`          | Policy processing not implemented            |
| `name_constraints_violated`                  | Name constraints check failed                |
| `initial_name_constraints_not_implemented`   | Initial name constraints not implemented     |
| `unsupported_name_constraints`               | Unsupported name constraint form             |
| `explicit_policy_required`                   | Policy required but not satisfied            |
| `initial_policy_set_not_satisfied`           | Initial policy set not met                   |
| `unsupported_signature_algorithm_parameters` | Unknown signature algorithm                  |

## CSR verification

```ts
import { verifyCertificateSigningRequest } from 'micro509';

const result = await verifyCertificateSigningRequest(
  csr.pem,
);

if (result.ok) {
  console.log('CSR signature valid');
}
```

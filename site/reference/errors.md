---
outline: [2, 3]
---

# Error Codes

Every expected failure in micro509 carries a machine-readable code. `Result`-returning
APIs put it on `result.error.code` (or `result.code` on flattened failures); builder
APIs that take developer-supplied config throw a coded error that `isResultError`
detects and `error.code` discriminates.

This page lists **every** public error-code union and its members, grouped by the
entrypoint that owns it. A repo test extracts these unions from the type declarations
and fails when this page and the exported types disagree, in either direction.

::: info Stability
Unions may gain members in minor releases; treat them as non-exhaustive and keep a
`default` branch. Renaming or removing a code only happens in a major release.
:::

## micro509/x509

### ParseCertificateErrorCode

| Code        | Meaning                                           |
| ----------- | ------------------------------------------------- |
| `malformed` | Input is not a valid DER or PEM X.509 certificate |

### ParseCertificateSigningRequestErrorCode

| Code        | Meaning                                         |
| ----------- | ----------------------------------------------- |
| `malformed` | Input is not a valid DER or PEM PKCS#10 request |

### MatchCertificatePrivateKeyErrorCode

| Code                      | Meaning                                       |
| ------------------------- | --------------------------------------------- |
| `key_mismatch`            | Right algorithm, different key                |
| `key_type_mismatch`       | Private key algorithm differs from the SPKI's |
| `malformed_certificate`   | Certificate source failed to parse            |
| `unsupported_private_key` | Key type has no supported SPKI derivation     |

### CreateCertificateErrorCode

| Code                                   | Meaning                                                  |
| -------------------------------------- | -------------------------------------------------------- |
| `issuer_distinguished_name_empty`      | RFC 5280 §4.1.2.4 requires a non-empty issuer DN         |
| `serial_number_not_positive`           | Serial must be a positive integer (RFC 5280 §4.1.2.2)    |
| `serial_number_too_long`               | Serial DER INTEGER exceeds 20 octets (RFC 5280 §4.1.2.2) |
| `validity_date_invalid`                | `notBefore`, `notAfter` or `days` gives an invalid date  |
| `validity_not_after_before_not_before` | Validity window ends before it starts                    |

### NameEncoderErrorCode

| Code                                | Meaning                                              |
| ----------------------------------- | ---------------------------------------------------- |
| `invalid_country_code`              | Country attribute is not exactly two letters         |
| `name_attribute_empty`              | Attribute value is empty (RFC 5280 A.1 `SIZE (1..)`) |
| `name_attribute_too_long`           | Attribute value exceeds its RFC 5280 A.1 upper bound |
| `relative_distinguished_name_empty` | RDN carries no attributes                            |
| `unsupported_name_field`            | Attribute key is not an encodable name field         |

### ExtensionEncoderErrorCode

| Code                                                    | Meaning                                                           |
| ------------------------------------------------------- | ----------------------------------------------------------------- |
| `authority_info_access_empty`                           | AIA input has no access descriptions                              |
| `authority_info_access_ocsp_not_uri`                    | An OCSP access method requires a URI location                     |
| `certificate_policies_empty`                            | certificatePolicies lists no policies                             |
| `crl_distribution_points_empty`                         | cRLDistributionPoints lists no points                             |
| `directory_name_not_sequence`                           | directoryName payload is not a DER SEQUENCE                       |
| `display_text_control_character`                        | explicitText contains a C0 or C1 control character (RFC 6818 §3)  |
| `display_text_ia5_string`                               | explicitText requested as IA5String (RFC 6818 §3)                 |
| `display_text_not_nfc`                                  | UTF8String or BMPString explicitText is not NFC (RFC 6818 §3)     |
| `display_text_out_of_range`                             | User-notice DisplayText length outside RFC 5280 bounds            |
| `distribution_point_crl_issuer_empty`                   | `cRLIssuer` present but holds no name                             |
| `distribution_point_crl_issuer_not_directory_name`      | `cRLIssuer` entries must be directoryNames (RFC 5280 §4.2.1.13)   |
| `distribution_point_empty`                              | Distribution point carries no field at all                        |
| `distribution_point_full_name_empty`                    | `fullName` present but holds no GeneralName                       |
| `distribution_point_relative_name_multiple_crl_issuers` | `nameRelativeToCRLIssuer` permits at most one `cRLIssuer`         |
| `duplicate_extension_oid`                               | Same extension OID supplied twice                                 |
| `duplicate_policy_oid`                                  | Same policy OID listed twice                                      |
| `edwards_key_usage_forbids_agreement_bit`               | Ed25519/Ed448 keyUsage asserts an agreement or cipher bit         |
| `edwards_key_usage_forbids_key_cert_sign`               | End-entity Edwards certificate asserts `keyCertSign`/`cRLSign`    |
| `edwards_key_usage_requires_key_cert_sign`              | Edwards CA keyUsage missing `keyCertSign`                         |
| `edwards_key_usage_requires_signing_bit`                | Edwards keyUsage missing a signing bit (RFC 9295 §3)              |
| `empty_general_name_value`                              | dNSName/rfc822Name/URI/SRV value is empty                         |
| `empty_subject_requires_subject_alt_name`               | Empty subject DN without a critical, non-empty SAN                |
| `extended_key_usage_empty`                              | EKU list is empty                                                 |
| `extension_must_be_critical`                            | RFC 5280 fixes this extension as critical                         |
| `extension_must_be_non_critical`                        | RFC 5280 fixes this extension as non-critical                     |
| `extension_not_supported_in_context`                    | Extension not allowed in this certificate/CSR context             |
| `invalid_bmp_string`                                    | BMPString explicitText outside the Basic Multilingual Plane       |
| `invalid_general_name_tag`                              | GeneralName tag outside the nine RFC 5280 §4.2.1.6 alternatives   |
| `invalid_ia5_string`                                    | Non-ASCII input for an IA5String value                            |
| `invalid_ip_name_constraint`                            | IP constraint bytes are not address+mask of one family            |
| `invalid_oid`                                           | String is not an encodable OID within X.660 arc bounds            |
| `invalid_visible_string`                                | VisibleString explicitText outside printable ASCII                |
| `key_usage_empty`                                       | keyUsage asserts no bits                                          |
| `malformed_known_extension_value`                       | `customExtensions` payload with a known OID fails to decode as it |
| `montgomery_key_usage_forbids_both_cipher_bits`         | X25519/X448 asserts both `encipherOnly` and `decipherOnly`        |
| `montgomery_key_usage_forbids_signature_bit`            | X25519/X448 asserts a signature bit (RFC 8410 §12)                |
| `montgomery_key_usage_requires_key_agreement`           | X25519/X448 keyUsage missing `keyAgreement` (RFC 9295 §3)         |
| `name_constraints_empty`                                | nameConstraints has neither permitted nor excluded subtrees       |
| `no_rev_avail_conflict`                                 | noRevAvail with cA or a revocation pointer (RFC 9608 §3)          |
| `path_length_requires_ca`                               | `pathLength` on a non-CA basicConstraints                         |
| `path_length_requires_key_cert_sign`                    | `pathLength` requires keyUsage asserting `keyCertSign`            |
| `policy_constraints_empty`                              | policyConstraints carries neither field                           |
| `policy_mappings_any_policy`                            | anyPolicy may not appear in a policy mapping                      |
| `policy_mappings_empty`                                 | Mappings list is empty                                            |
| `reserved_policy_qualifier_oid`                         | Custom qualifier uses a reserved qualifier OID                    |

## micro509/verify

### VerifyErrorCode

Meanings are tabled in the [verification guide](../guide/verification.md#error-codes);
both tables are enforced against `VERIFY_ERROR_CODES` by tests.

`authority_key_identifier_mismatch`, `ca_required`, `certificate_expired`,
`certificate_revoked`, `common_name_fallback_suppressed`,
`ec_domain_parameters_missing`, `explicit_policy_required`,
`extended_key_usage_invalid`, `initial_policy_set_not_satisfied`,
`intermediate_eku_constraint`, `issuer_not_found`, `key_cert_sign_required`,
`name_constraints_violated`, `no_rev_avail_conflict`, `no_trusted_root`,
`path_length_exceeded`,
`path_building_limit_exceeded`,
`revocation_indeterminate`, `self_signed_leaf_not_allowed`, `signature_invalid`,
`subject_alt_name_mismatch`, `unrecognized_critical_extension`,
`unsupported_initial_name_constraints`, `unsupported_name_constraints`,
`unsupported_signature_algorithm_parameters`

### MatchServiceIdentityErrorCode

| Code                                | Meaning                                      |
| ----------------------------------- | -------------------------------------------- |
| `common_name_fallback_suppressed`   | CN match suppressed by presented identifiers |
| `service_identity_mismatch`         | SRV-ID or URI-ID service part does not match |
| `subject_alt_name_mismatch`         | No SAN matches the requested identity        |
| `unsupported_service_identity_type` | Identity type has no matcher                 |

## micro509/revocation

### ParseCertificateRevocationListErrorCode

| Code        | Meaning                             |
| ----------- | ----------------------------------- |
| `malformed` | Input is not a valid DER or PEM CRL |

### ParseOcspRequestErrorCode

| Code        | Meaning                                      |
| ----------- | -------------------------------------------- |
| `malformed` | Input is not a valid DER or PEM OCSP request |

### ParseOcspResponseErrorCode

| Code        | Meaning                                       |
| ----------- | --------------------------------------------- |
| `malformed` | Input is not a valid DER or PEM OCSP response |

### CheckCertificateRevocationAgainstCrlErrorCode

| Code                     | Meaning                                                                   |
| ------------------------ | ------------------------------------------------------------------------- |
| `crl_sign_not_permitted` | CRL signer's keyUsage lacks `cRLSign`, or a v3 signer has no keyUsage     |
| `issuer_mismatch`        | CRL issuer does not match the certificate's issuer                        |
| `non_applicable`         | No supplied CRL applies to the certificate (RFC 5280 §6.3.3)              |
| `signature_invalid`      | CRL signature fails against the issuer key                                |
| `stale_crl`              | CRL outside its `thisUpdate`/`nextUpdate` window or older than `maxAgeMs` |

A `non_applicable` failure carries a `reason`. `delta_crl_incompatible` covers a
delta CRL that does not pair with the complete CRL, including one whose
`thisUpdate` precedes the complete CRL's `thisUpdate`.

### ValidateOcspResponseErrorCode

| Code                           | Meaning                                                                |
| ------------------------------ | ---------------------------------------------------------------------- |
| `issuer_mismatch`              | CertID does not hash to the supplied issuer                            |
| `next_update_missing`          | A response omits `nextUpdate` under `profile: 'rfc9919'` (RFC 9919 §5) |
| `nonce_mismatch`               | Response nonce differs from the request's                              |
| `ocsp_signing_missing`         | Delegated responder lacks the `ocspSigning` EKU                        |
| `request_mismatch`             | Response does not answer every requested CertID                        |
| `responder_chain_invalid`      | Responder certificate path fails validation                            |
| `responder_id_mismatch`        | ResponderID matches no candidate signer                                |
| `responder_revocation_unknown` | Delegated responder revocation status undetermined                     |
| `responder_revoked`            | Delegated responder certificate is revoked                             |
| `response_status_invalid`      | OCSPResponse status is not `successful`                                |
| `signature_invalid`            | Response signature fails                                               |
| `stale_response`               | Response outside its freshness window                                  |

### CheckCertificateRevocationErrorCode

| Code                              | Meaning                                                |
| --------------------------------- | ------------------------------------------------------ |
| `revocation_evidence_missing`     | No CRL or OCSP evidence was supplied                   |
| `revocation_status_indeterminate` | Evidence yielded no verdict under the hard-fail policy |

### RevocationIndeterminateReasonCode

| Code                           | Meaning                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `certificate_status_missing`   | Response carries no entry for the certificate                                |
| `certificate_status_unknown`   | Responder answered `unknown`                                                 |
| `crl_sign_not_permitted`       | CRL signer's keyUsage lacks `cRLSign`, or a v3 signer has no keyUsage        |
| `issuer_mismatch`              | Evidence issuer does not match the certificate's issuer                      |
| `next_update_missing`          | OCSP response omits `nextUpdate` under `ocspProfile: 'rfc9919'`              |
| `non_applicable`               | No supplied CRL applies to the certificate                                   |
| `nonce_mismatch`               | Response nonce differs from the request's                                    |
| `ocsp_signing_missing`         | Delegated responder lacks the `ocspSigning` EKU                              |
| `reason_coverage_incomplete`   | Applicable CRLs cover only some CRLReasons                                   |
| `request_mismatch`             | Response does not answer the supplied request                                |
| `responder_chain_invalid`      | Responder certificate path fails validation                                  |
| `responder_id_mismatch`        | ResponderID matches no candidate signer                                      |
| `responder_revocation_unknown` | Delegated responder revocation status undetermined                           |
| `responder_revoked`            | Delegated responder certificate is revoked                                   |
| `response_status_invalid`      | OCSPResponse status is not `successful`                                      |
| `signature_invalid`            | Evidence signature fails                                                     |
| `stale_crl`                    | CRL outside its `thisUpdate`/`nextUpdate` window or older than `crlMaxAgeMs` |
| `stale_response`               | Response outside its freshness window                                        |

The chain-level `RevocationIndeterminateReason` from `checkChainRevocation` and
`verifyCertificateChain({ revocation })` uses its own names. A CRL that is
outside its window or older than `crlMaxAgeMs` is reported as `crl_expired`,
and an OCSP response without `nextUpdate` under `ocspProfile: 'rfc9919'` as
`ocsp_next_update_missing`.

### CrlEncoderErrorCode

| Code                                 | Meaning                                                       |
| ------------------------------------ | ------------------------------------------------------------- |
| `distribution_point_full_name_empty` | IDP `fullName` present but holds no GeneralName               |
| `issuer_distinguished_name_empty`    | RFC 5280 §5.1.2.3 requires a non-empty issuer DN              |
| `invalid_date`                       | A CRL or revoked-entry date is an invalid `Date`              |
| `next_update_not_after_this_update`  | `nextUpdate` does not encode a later second than `thisUpdate` |

### OcspEncoderErrorCode

| Code                              | Meaning                                                  |
| --------------------------------- | -------------------------------------------------------- |
| `invalid_date`                    | A response date is an invalid `Date`                     |
| `signer_certificate_key_mismatch` | Signer certificate's SPKI does not match the signing key |

## micro509/keys

### ImportKeyErrorCode

| Code        | Meaning                                          |
| ----------- | ------------------------------------------------ |
| `malformed` | Key material fails to parse or match the request |

### ImportEncryptedKeyErrorCode

| Code                      | Meaning                                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_password`        | Decryption failed, or plaintext is not a private key                                                                                          |
| `kdf_iterations_exceeded` | PBKDF2 iteration count exceeds `maxKdfIterations` (2,000,000 default)                                                                         |
| `malformed`               | Envelope fails to parse before any decryption, including a PBKDF2 `iterationCount` outside 1 to 4294967295 whatever `maxKdfIterations` allows |

### EncryptRsaOaepErrorCode

| Code               | Meaning                                                |
| ------------------ | ------------------------------------------------------ |
| `invalid_key`      | Key is not an RSA-OAEP public key with `encrypt` usage |
| `message_too_long` | Plaintext exceeds the OAEP capacity of the key         |

### DecryptRsaOaepErrorCode

| Code                | Meaning                                                        |
| ------------------- | -------------------------------------------------------------- |
| `decryption_failed` | Deliberately opaque: wrong key, wrong label, or bad ciphertext |
| `invalid_key`       | Key is not an RSA-OAEP private key with `decrypt` usage        |

## micro509/pem

### PemErrorCode

| Code        | Meaning                                               |
| ----------- | ----------------------------------------------------- |
| `malformed` | Encapsulation or base64 violates RFC 7468 strict mode |

## micro509/der

### DecodeDerErrorCode

| Code        | Meaning                                  |
| ----------- | ---------------------------------------- |
| `malformed` | Bytes are not the expected DER structure |

## micro509/pkcs

### ParsePfxErrorCode

| Code                        | Meaning                                                                                                                                                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_password`          | MAC or decryption rejects the supplied password                                                                                                                                                                   |
| `kdf_iterations_exceeded`   | The PBES2 bags' combined PBKDF2 iteration counts exceed `maxKdfIterations` (2,000,000 default), or the MAC's count exceeds its own `maxKdfIterations` (100,000 default for the PKCS#12 KDF, 2,000,000 for PBMAC1) |
| `malformed`                 | PFX structure fails to parse, including a PBKDF2 `iterationCount` outside 1 to 4294967295 in a PBES2 bag or a PBMAC1 MAC                                                                                          |
| `password_not_bmp_string`   | The RFC 7292 MAC password (`macPassword`, or `password` as fallback) contains a UTF-16 surrogate                                                                                                                  |
| `password_not_utf8`         | The PBMAC1 password contains an unpaired UTF-16 surrogate                                                                                                                                                         |
| `password_required`         | Encrypted content present but no password given                                                                                                                                                                   |
| `unsupported_mac_algorithm` | The MAC is neither the SHA-256 RFC 7292 MAC nor a supported PBMAC1 variant                                                                                                                                        |
| `weak_mac_key_length`       | PBMAC1 PBKDF2 `keyLength` is below 20 octets                                                                                                                                                                      |

### CreatePfxErrorCode

| Code                  | Meaning                             |
| --------------------- | ----------------------------------- |
| `invalid_certificate` | A certificate source fails to parse |

### CreatePkcs12MacDataErrorCode

`createPkcs12MacData`, and `createPfx` through its `mac` option, throw these as a
`ResultError`.

| Code                      | Meaning                                                                                                    |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `invalid_iterations`      | `iterations` is not a positive safe integer (RFC 7292 MAC) or not an integer from 1 to 4294967295 (PBMAC1) |
| `password_not_bmp_string` | RFC 7292 MAC password contains a UTF-16 surrogate                                                          |
| `password_not_utf8`       | PBMAC1 password contains an unpaired UTF-16 surrogate                                                      |

### ParsePkcs12MacDataErrorCode

| Code                        | Meaning                                                                                                                                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kdf_iterations_exceeded`   | With a password, the iteration count exceeds `maxKdfIterations` (100,000 default for the PKCS#12 KDF, 2,000,000 for PBMAC1), or an RFC 7292 MAC count exceeds `Number.MAX_SAFE_INTEGER`                                |
| `malformed`                 | MacData structure fails to parse, an iteration count is below 1, a PBMAC1 count exceeds 4294967295 whatever `maxKdfIterations` allows, or, without a password, an RFC 7292 MAC count exceeds `Number.MAX_SAFE_INTEGER` |
| `password_not_bmp_string`   | RFC 7292 MAC password contains a UTF-16 surrogate                                                                                                                                                                      |
| `password_not_utf8`         | PBMAC1 password contains an unpaired UTF-16 surrogate                                                                                                                                                                  |
| `unsupported_mac_algorithm` | The MAC is neither the SHA-256 RFC 7292 MAC nor a supported PBMAC1 variant                                                                                                                                             |
| `weak_mac_key_length`       | PBMAC1 PBKDF2 `keyLength` is below 20 octets                                                                                                                                                                           |

Without a password no key is derived. `maxKdfIterations` is not applied, and
`verification` is `'unchecked'` for any RFC 7292 MAC count from 1 to
`Number.MAX_SAFE_INTEGER` and any PBMAC1 count from 1 to 4294967295.

### ParsePkcs7ErrorCode

| Code              | Meaning                                            |
| ----------------- | -------------------------------------------------- |
| `malformed`       | ContentInfo or SignedData fails to parse           |
| `not_signed_data` | ContentInfo carries a content type other than data |

### CreatePkcs7CertBagErrorCode

| Code                  | Meaning                             |
| --------------------- | ----------------------------------- |
| `invalid_certificate` | A certificate source fails to parse |

### CreatePkcs7SignedDataErrorCode

| Code                              | Meaning                                                  |
| --------------------------------- | -------------------------------------------------------- |
| `invalid_certificate`             | An `additionalCertificates` entry fails to parse         |
| `invalid_signer_certificate`      | A signer's certificate source fails to parse             |
| `no_signers`                      | `signers` is empty                                       |
| `signer_certificate_key_mismatch` | Signer certificate's SPKI does not match the signing key |
| `unsupported_signer_key`          | Signing key algorithm has no CMS digest mapping          |

### VerifyPkcs7SignedDataErrorCode

| Code                        | Meaning                                                       |
| --------------------------- | ------------------------------------------------------------- |
| `detached_content_required` | SignedData has no `eContent` and no `content` option supplied |
| `malformed`                 | Structure, attributes, or algorithms fail to process          |
| `message_digest_mismatch`   | Content digest differs from the `messageDigest` attribute     |
| `no_signers`                | `signerInfos` is empty                                        |
| `not_signed_data`           | ContentInfo carries a content type other than SignedData      |
| `signature_invalid`         | A signer's signature does not verify                          |
| `signer_not_found`          | No embedded certificate matches a SignerInfo                  |

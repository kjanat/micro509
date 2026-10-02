# PKIX validation scope and roadmap

This file is the canonical support boundary, claim-language guide, and
forward-work backlog for the PKIX-facing surface.

## Standards status

| Area                                                                                    | Status     | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RFC 5280][rfc5280] path validation                                                     | `complete` | core path validation, name constraints across all GeneralName forms (enforce or fail-closed), initial subtree inputs, [RFC 9618][rfc9618] policy processing, and malformed-DER coverage ship; validated against the full NIST PKITS suite (224 test procedures, 249 runs incl. documented subtest variations; 4.1.4/4.1.5 DSA chains expected-fail per the WebCrypto algorithm boundary). Revocation is a separate API by design                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| [RFC 6960][rfc6960] + [9919][rfc9919] OCSP                                              | `complete` | the full validation surface ships: request/response parsing, signature checks, responder binding/authorization (incl. local trusted responders, `id-pkix-ocsp-nocheck`, and responder revocation policy), nonce/request matching, freshness checks, full request coverage, and chain-level revocation orchestration with freshest-evidence combination; CertID hashing defaults to SHA-256 per [RFC 9919 §3.1.1][rfc9919-section-3.1.1] with explicit SHA-1 interop; the [RFC 9919][rfc9919] client rule is opt-in, and `profile: 'rfc9919'` on `validateOcspResponse` (`ocspProfile: 'rfc9919'` on `checkCertificateRevocation` and the chain `RevocationPolicy`) rejects a response without `nextUpdate` ([RFC 9919 §5][rfc9919-section-5]), and the default `'rfc6960'` profile accepts it ([RFC 6960 §4.2.2.1][rfc6960-section-4.2.2.1]); HTTP transport is caller-provided by design |
| [RFC 9525][rfc9525] service identity                                                    | `complete` | `matchServiceIdentity()` and the verification helpers (`verifyCertificateChain`, `validateForTlsServer`, …) ship every [RFC 9525][rfc9525] identity type: DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in [RFC 6125][rfc6125] CN-compat checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [RFC 9618][rfc9618] policy validation                                                   | `complete` | [RFC 9618][rfc9618]-style policy state, enforcement, and outputs ship; the full PKITS policy sections (4.8–4.12, every documented subtest variation) pass                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [RFC 7468][rfc7468] PEM textual encodings                                               | `complete` | strict generator/parser conformance: strict-mode encapsulation, label handling, and base64 rules ship, with non-canonical final quanta rejected per [RFC 4648 §3.5][rfc4648-section-3.5]; [RFC 1421][rfc1421] folded encapsulated headers unfold for legacy traditional PEM; section-complete executable suite                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [RFC 8410][rfc8410] + [9295][rfc9295] safe-curve profiles                               | `complete` | Ed25519 end-to-end (key import/export/generation, CSRs, certificates, signature verification); Ed448/X25519/X448 algorithm identifiers and subject keys parse, with [RFC 9295 §3][rfc9295-section-3] key-usage enforcement for all four OIDs; Ed448/X25519/X448 key operations sit outside the WebCrypto algorithm boundary; section-complete executable suite                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| PKCS containers: [RFC 5652][rfc5652], [7292][rfc7292], [8018][rfc8018], [9879][rfc9879] | `partial`  | SignedData sign/parse/verify with per-signer certificate resolution and cert bags ([RFC 5652][rfc5652] subset; no enveloped/encrypted content types); PFX create/parse with BER input, a SHA-256-only [RFC 7292][rfc7292] MAC, and [RFC 9879][rfc9879] PBMAC1 verification plus opt-in creation ([RFC 7292][rfc7292] subset, see §15); PBES2 with PBKDF2 HMAC-SHA-1/256 and AES-CBC ([RFC 8018][rfc8018] subset)                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

Current conformance evidence:

- [`test/pkits.test.ts`](../test/pkits.test.ts),
- [`test/policy.test.ts`](../test/policy.test.ts),
- [`test/name-constraints.test.ts`](../test/name-constraints.test.ts),
- [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts),
- [`test/identity-fixtures.test.ts`](../test/identity-fixtures.test.ts),
- [`test/revocation.test.ts`](../test/revocation.test.ts),
- [`test/chain-revocation.test.ts`](../test/chain-revocation.test.ts),
- [`test/malformed-der.test.ts`](../test/malformed-der.test.ts),
- [`test/rfc/rfc7468.test.ts`](../test/rfc/rfc7468.test.ts),
- [`test/rfc/rfc8410.test.ts`](../test/rfc/rfc8410.test.ts),
- [`test/pkcs7-signeddata.test.ts`](../test/pkcs7-signeddata.test.ts),
- [`test/pfx.test.ts`](../test/pfx.test.ts),
- [`test/rfc/rfc5280-crl.test.ts`](../test/rfc/rfc5280-crl.test.ts),
- [`test/rfc/rfc5280-der.test.ts`](../test/rfc/rfc5280-der.test.ts),
- [`test/rfc/rfc7292.test.ts`](../test/rfc/rfc7292.test.ts),
- [`test/rfc/rfc8018.test.ts`](../test/rfc/rfc8018.test.ts),
- [`test/rfc/rfc9879.test.ts`](../test/rfc/rfc9879.test.ts),
- [`test/rfc/rfc9919.test.ts`](../test/rfc/rfc9919.test.ts), and
- [`test/differential.test.ts`](../test/differential.test.ts).

## 1. Define the boundary up front

- [x] Treat **certification path validation** as a function over a
      **prospective certification path** plus validation inputs, not as
      “build whatever chain you can find and hope for the best.”

      [RFC 5280][rfc5280] Section 6.1.1 defines the algorithm in terms of a candidate path
      and nine inputs. (IETF Datatracker[^rfc5280])

- [x] Keep **path building/discovery** separate from **path validation**.
- [x] Keep **service identity matching** separate from **path validation**.
- [x] Keep **revocation** separate from **path validation**.

## 2. Required inputs for RFC 5280-style path validation

- [x] Prospective certification path.
- [x] Validation time.
- [x] Trust anchor information: trusted issuer name,
      trusted public key algorithm,
      trusted public key, and optional trusted key parameters.
- [x] User-initial-policy-set. A list holding the anyPolicy OID means
      any-policy. A supplied list must be satisfied even when explicit policy
      is not required: [RFC 9618 §5.5][rfc9618-section-5.5] would accept an empty user-constrained
      policy set there, and micro509 applies the stricter rule as the
      application restriction [RFC 9618 §5.1][rfc9618-section-5.1] allows.
- [x] Initial policy-mapping inhibit flag.
- [x] Initial explicit-policy flag.
- [x] Initial anyPolicy-inhibit flag.
- [x] Initial permitted subtrees.
- [x] Initial excluded subtrees. (IETF Datatracker[^rfc5280])

## 3. Core certificate/path checks

- [x] Emit DER from every encoder, and reject malformed certificates on parse.
      As local policy (X.509 §7.2.1 NOTE 2), parsers tolerate an explicitly
      encoded DEFAULT value: certificate version v1, extension `critical`
      FALSE, basicConstraints `cA` FALSE, and OCSP request and response
      version v1. A BOOLEAN whose content is not a single `0x00` or `0xFF`
      octet is rejected as malformed (X.690 §11.1). PKCS#12 input may be BER;
      see §15.
- [x] Encode, decode and canonicalize OBJECT IDENTIFIER arcs with arbitrary
      precision. X.660 §7.6 leaves arc values unbounded, and [RFC 5280
      Appendix B][rfc5280-appendix-B] states "There is no maximum size for OIDs"; its 2^28 arc,
      100-byte and 20-element figures are the minimum an implementation must
      support. micro509 bounds one sub-identifier's base-128 encoding at 64
      octets (values below 2^448) as an implementation limit, checked before
      any of the arc is accumulated. Decoding an arc grows quadratically with
      its octets (`bench/oid-bench.ts`: 1,000 octets in 1 ms, 10,000 in 22 ms,
      100,000 in 1.1 s on the reference machine), and the bound keeps a parse
      linear in its input. A longer arc returns `limit_exceeded` from every
      parser, and the builder refuses it with `invalid_oid`.
- [x] Decode a TeletexString Name attribute value in the initial state X.690
      §8.23.5.2 fixes: register entry 102, the T.61 primary set, read by T.61
      Table 1 with 2/3 as # and 2/4 as ¤ (T.61 Figure 2 Note 4), plus the SPACE
      and DELETE of X.680 Table 8. No standard maps TeletexString to Unicode
      ([RFC 4518 §2.1][rfc4518-section-2.1]); micro509 maps each character to the ISO/IEC 10646
      character of the same name, as the [RFC 1345][rfc1345] `T.61-7bit` table does.
      Octets below 0x20 (the C0 control functions, ESC and the shifts among
      them), the six positions T.61 Table 1 leaves empty, and octets from 0x80
      up (C1 and the right half, where X.690 designates nothing) are
      unsupported, and the parse returns `unsupported` rather than `malformed`,
      since micro509 does not decode them and X.690 and T.61 disagree on the
      right half. [RFC 5280 §7.1][rfc5280-section-7.1] makes TeletexString support optional and
      defines a match as the same attribute type with values equal after [RFC
      4518][rfc4518] preparation, which transcodes a TeletexString by a local mapping
      ([RFC 4518 §2.1][rfc4518-section-2.1]) before the remaining steps; micro509 prepares the decoded
      value like the other DirectoryString alternatives, so it matches a
      UTF8String or PrintableString value with the same characters, in
      issuer/subject chaining, CRL and OCSP issuer matching and directoryName
      name constraints. A TeletexString value micro509 cannot decode fails the
      parse of a certificate, CRL, OCSP message or PKCS#7 signer; inside a
      directoryName name constraint it fails every subject DN and directoryName
      SAN while the constraint is in force ([RFC 4518 §2][rfc4518-section-2] makes a failed
      preparation Undefined, and [RFC 5280][rfc5280] leaves the consequence unspecified).
      A decoded value that preparation refuses, such as one holding a
      private-use character, makes its comparison Undefined as well. In a
      directoryName name constraint an Undefined comparison fails an excluded
      subtree and does not satisfy a permitted one. A multi-valued RDN is
      Undefined when no one-to-one pairing of its attributes matches every
      pair but one does with Undefined pairs allowed. Matching an RDN takes time
      linear in its attribute count. Issuer/subject chaining and
      CRL and OCSP issuer matching treat it as no match.
- [x] Verify issuer/subject chaining across the candidate path.
- [x] Verify each certificate signature using the evolving working public key.
- [x] Check validity time (`notBefore` / `notAfter`) against the chosen validation time.
- [x] Enforce `basicConstraints` for CA certificates.
- [x] Enforce `pathLenConstraint` where applicable.
- [x] Enforce `keyUsage`, especially `keyCertSign` for CAs used to sign subordinate certs.
- [x] Process self-issued vs non-self-issued certs correctly for path length and name constraints.
- [x] Reject a certificate whose `id-ecPublicKey` key locates no namedCurve domain
      parameters. (IETF Datatracker[^rfc5480])
- [x] Reject the path if any required path-processing step fails. (IETF Datatracker[^rfc5280])

## 4. Extension handling

- [x] Parse and preserve all extensions, including unknown ones.
- [x] Reject certificates containing an **unsupported critical extension** or a
      critical extension whose contents cannot be processed.
- [x] Process recognized non-critical extensions when relevant to path processing.
- [x] Expose raw extension data so callers can layer application-specific policy on top. (IETF Datatracker[^rfc5280])

## 5. Name constraints

- [x] Support `nameConstraints` on CA certificates.
- [x] Support initial permitted/excluded subtrees as validator inputs.
- [x] Apply constraints across supported name forms, not just DNS SANs.
- [x] Handle self-issued certificates correctly when evaluating constraints.
- [x] Enforce SRVName restrictions per [RFC 4985 §4][rfc4985-section-4]: `_Service.Name`,
      `_Service`, or `Name`, the service matched case-insensitively and the
      Name matching that domain and its subdomains label by label.
- [x] Accept a SRVName Name, in a SAN or a restriction, that ends in the
      dot of an absolute name, and keep it as written. Restriction matching
      and SRV-ID matching compare the Name's labels without the root label,
      which [RFC 3490 §2][rfc3490-section-2] does not count as a label, so `_mail.example.com.`
      and `_mail.example.com` match each other ([RFC 3490 §3.1][rfc3490-section-3.1] requirement 4).
      An empty label elsewhere, a repeated terminal dot and an empty Name are
      malformed.
- [x] Hold every SRVName, in typed SANs, typed and initial restrictions, and
      received names and restrictions under evaluation, to one syntax. The
      service is an [RFC 6335 §5.1][rfc6335-section-5.1] service name (1 to 15 letters, digits and
      hyphens, at least one letter, no leading, trailing or adjacent hyphen).
      [RFC 4985 §2][rfc4985-section-2] requires the components to be consistent with an [RFC 2782][rfc2782]
      SRV RR, and [RFC 6335 §5.2][rfc6335-section-5.2], which updates [RFC 2782][rfc2782], requires the Service
      Label to be such a name. The Name is STD3 LDH labels ([RFC 4985 §3][rfc4985-section-3]).
      U+3002, U+FF0E and U+FF61 are stored as U+002E ([RFC 4985 §3][rfc4985-section-3]). Holding a
      received Name's `xn--` labels to IDNA2008 A-labels is micro509's
      choice; [RFC 4985][rfc4985] requires conversion only when a Name is stored.
      [RFC 4985][rfc4985] gives a relying party no rule for a received restriction
      outside this syntax. micro509 cannot evaluate one, counts it as
      malformed and rejects every SRVName while it is in force, as [RFC 5280
      §4.2][rfc5280-section-4.2] requires for a critical extension holding information that cannot
      be processed.
- [x] Match a dNSName constraint that starts with a period, such as
      `.example.com`, against subdomains only. `www.example.com` and
      `a.b.example.com` fall inside it, and `example.com` does not. [RFC 5280
      §4.2.1.10][rfc5280-section-4.2.1.10] defines the leading period for URI and rfc822Name constraints
      only, and erratum [5997][eid5997] (Held for Document Update) records the readings
      for dNSName. OpenSSL, BoringSSL, Go, NSS, mozilla::pkix and
      rustls-webpki all match subdomains only.
- [x] Hold every URI constraint, typed, initial or received, to [RFC 5280
      §4.2.1.10][rfc5280-section-4.2.1.10] and [Appendix B][rfc5280-appendix-B]: a DNS name in A-labels, which names one host,
      or the same with a leading period, which names its subdomains only.
      [RFC 5280][rfc5280] sets no label syntax for a URI constraint or a URI SAN host,
      and [RFC 3986][rfc3986] lets a reg-name hold "\_". micro509 takes ASCII labels of 1
      to 63 letters, digits, hyphens and underscores for both, so a
      constraint and the hosts it is matched against share one alphabet. The
      builder and the initial-constraint input refuse a full URI such as
      `https://blocked.example`, a port or path, an IP address, a root dot and
      a U-label. A received constraint of that kind is malformed, and every URI
      SAN is rejected while it is in force ([RFC 5280 §4.2][rfc5280-section-4.2]). [RFC 5280][rfc5280] does not
      define an empty URI constraint; micro509 matches it against every host,
      as for dNSName.
- [x] Read a URI SAN's host once, by [RFC 3986][rfc3986], for URI constraints and URI-ID
      matching alike: the authority after `//`, past any userinfo and before
      any port. A userinfo outside [RFC 3986 §3.2.1][rfc3986-section-3.2.1], such as `bad%zz`, or a
      path, query or fragment outside [§3.3][rfc3986-section-3.3] to [§3.5][rfc3986-section-3.5], such as `/%zz`, makes the
      host invalid. A reference identifier follows the [RFC 3987 §2.2][rfc3987-section-2.2] IRI
      grammar instead, without the bidirectional formatting characters of
      [§4.1][rfc3987-section-4.1]. A percent-encoded unreserved character decodes, so
      `ldap://%62locked.example/` has the host `blocked.example` ([RFC 3986
      §2.3][rfc3986-section-2.3] and [§6.2.2.2][rfc3986-section-6.2.2.2], [RFC 5280 §7.4][rfc5280-section-7.4] step 3). Other percent-encoded octets
      stay encoded: [RFC 3986 §6][rfc3986-section-6] does not make a percent-encoded U-label equal
      its A-label, and [RFC 9525 §2][rfc9525-section-2] requires A-labels in a presented URI-ID, so
      `https://b%C3%BCcher.example/` is not a domain name. The single dot [RFC 3986
      §3.2.2][rfc3986-section-3.2.2] allows after the rightmost label is dropped. No normalization rule
      makes `blocked.example.` equal `blocked.example`; reading both as one
      FQDN is micro509's choice. Under any URI constraint the certificate is
      rejected when a URI SAN has no authority, an IP host, a single-label host
      such as `localhost`, or a reg-name that is not a domain name after
      decoding, such as `blocked.example;extra` (";" is a sub-delim) or
      `*.example.com` ([RFC 5280 §4.2.1.10][rfc5280-section-4.2.1.10]).
- [x] Fail closed per [RFC 5280 §4.2.1.10][rfc5280-section-4.2.1.10] when a **critical** nameConstraints
      extension imposes a form whose constraint-matching semantics micro509
      does not implement
      (`x400Address`, `ediPartyName`, `registeredID`, and every `otherName`
      type-id other than SRVName) **and** an instance of that form appears in
      a subsequent certificate's SANs. Each `otherName` type-id is its own
      form (X.509 §9.4.2.2), so a UPN constraint does not reject an SRVName or
      SmtpUTF8Mailbox. Chains where the form never appears stay acceptable,
      unsupported forms in non-critical extensions are ignored, and initial
      constraints of these forms are refused.
      (IETF Datatracker[^rfc5280])

Current GeneralName matrix for `nameConstraints`:

| Form                        | Parser role                      | Validator role                                        | Status     |
| --------------------------- | -------------------------------- | ----------------------------------------------------- | ---------- |
| `rfc822Name` / `dNSName`    | decode to typed email/DNS values | enforce                                               | `complete` |
| `uniformResourceIdentifier` | decode to typed URI values       | enforce host-based matching                           | `complete` |
| `iPAddress`                 | decode to address+mask bytes     | enforce                                               | `complete` |
| `directoryName`             | preserve structured DN payload   | enforce with [RFC 5280][rfc5280] semantic compare     | `complete` |
| SmtpUTF8Mailbox `otherName` | decode to typed mailbox values   | enforce rfc822Name constraints by domain              | `complete` |
| SRVName `otherName`         | decode to typed SRVName values   | enforce [RFC 4985 §4][rfc4985-section-4] restrictions | `complete` |
| other `otherName`           | decode type-id and value DER     | fail closed per type-id when critical                 | `complete` |
| `x400Address`               | preserved as raw payload         | fail closed when critical and form appears            | `complete` |
| `ediPartyName`              | preserved as raw payload         | fail closed when critical and form appears            | `complete` |
| `registeredID`              | decoded OID, preserved           | fail closed when critical and form appears            | `complete` |

- Typing a GeneralName alternative is separate from supporting it. A critical
  subjectAltName carrying an `otherName` of an unrecognised type-id, an
  `x400Address` or an `ediPartyName` is an unprocessed critical extension. A
  `registeredID` is processed, since its whole value is an OID; its name
  constraints still fail closed, and it satisfies no DNS, URI or SRV identity.
- The builder validates the representation it emits. An `otherName` value is
  one DER element. Every universal-class element inside it, at any depth, has
  the form and contents X.690 fixes for its tag, DER's clauses 10 and 11
  included, and none is end-of-contents (X.690 §8.1.5, §10.1). TeletexString
  and VideotexString (ISO-IR repertoires), escape sequences and
  code-extension controls (ISO/IEC 2022), TIME and a GeneralizedTime at second
  60 (ISO 8601), a REAL with a long-form exponent (ambiguous in X.690
  §8.5.7.4 d)), EXTERNAL, EMBEDDED PDV and CHARACTER STRING (implicitly
  tagged contents), and the types of UNIVERSAL 31 to 36 are refused as
  unsupported. A SET or SET OF must list its children in the DER SET order
  (X.690 §10.3) or the DER SET OF order (§11.6). micro509 does not know the
  schema behind an arbitrary type-id, so contents under context-specific,
  application and private tags stay unchecked, as do DEFAULT omission and
  NamedBitList trailing bits. An `ediPartyName` holds an
  optional `[0]` and a
  required `[1]` DirectoryString, and an `x400Address` follows the [RFC 5280
  Appendix A.1][rfc5280-appendix-A.1] ORAddress schema: fields, tags, order, multiplicity, string
  repertoires and upper bounds, with DER SET ordering. TeletexString, the
  Teletex extension attributes (types 2 to 6), extended-network-address
  (type 22) and extension-attribute types [RFC 5280][rfc5280] does not define are
  refused as unsupported. Parsing keeps both forms as opaque bytes.

- Domain names follow IDNA2008 ([RFC 5890][rfc5890]-5893, [RFC 8753][rfc8753]). The derived
  property values, the Unicode properties the contextual and Bidi rules read,
  and the [RFC 5895][rfc5895] width decompositions are frozen to Unicode 12.0.0; NFC and
  case mapping come from the runtime. The builder converts U-labels to
  A-labels in dNSName and rfc822Name SANs, SmtpUTF8Mailbox domains, the Name
  of a SRVName and SRVName restriction, and dNSName and rfc822Name
  constraints, and checks every
  `xn--` label round trips, under the [RFC 5891 §4][rfc5891-section-4] registration tests.
  Caller-supplied initial DNS and mail constraints convert under the [§5][rfc5891-section-5]
  lookup tests. A reference identifier converts after [RFC 5895][rfc5895] mapping ([RFC
  9525 §6.3][rfc9525-section-6.3]). A reference URI-ID's host decodes its percent-encoded octets as
  UTF-8 ([RFC 3986 §3.2.2][rfc3986-section-3.2.2]) before that conversion. A presented URI host is not
  converted.
- [RFC 4985 §3][rfc4985-section-3] requires the IDNA2003 ToASCII conversion of [RFC 3490 §4][rfc3490-section-4]
  before a SRVName Name is stored. [RFC 5890][rfc5890] and [RFC 5891][rfc5891] obsolete [RFC 3490][rfc3490],
  and no RFC moves SRVName to IDNA2008. micro509 converts the Name with
  IDNA2008, as [RFC 9549][rfc9549] requires for dNSName, so a label on which the two
  disagree, such as one holding U+00DF, converts differently. The frozen
  Unicode 12.0.0 tables and the refusal of a label IDNA2008 disallows are
  micro509's choices.
- A name with no IDN label passes the builder unchecked, so a successful
  conversion does not establish that the whole name is a valid DNS name.
  ASCII labels beside an IDN label must be NR-LDH.
- rfc822Name constraints that name a particular mailbox were removed by [RFC
  9549 §2.2][rfc9549-section-2.2]. The builder and caller-supplied initial constraints refuse them.
  One in an already-issued certificate keeps its exact local-part match
  against an rfc822Name, and matches a SmtpUTF8Mailbox by domain alone as [RFC
  9598 §6][rfc9598-section-6] describes.
- Parser responsibility: preserve enough tag/type information that validation can make a deterministic supported-vs-unsupported decision.
- Validator responsibility: enforce supported forms and reject critical under-enforced cases instead of silently widening trust.

## 6. Certificate policy processing

- [x] Support `certificatePolicies`.
- [x] Parse each user-notice DisplayText (`explicitText` and the `noticeRef`
      organization) as the ASN.1 type its tag names: a valid UTF8String,
      IA5String, VisibleString or BMPString ([RFC 5280 §4.2.1.4][rfc5280-section-4.2.1.4]), returned
      unchanged. An empty DisplayText and any other encoding fail the parse
      as `malformed`. A DisplayText over 200 characters is kept whole and
      reported with its character count, as `oversizedExplicitText` on the
      qualifier or `oversizedOrganization` on the `noticeRef`; its length is
      bounded by the input alone, and decoding it is linear. [§4.2.1.4][rfc5280-section-4.2.1.4] asks
      certificate users to handle an oversized `explicitText` gracefully. It
      says nothing about an oversized organization, and keeping one is
      micro509's receiving policy. Path validation accepts both by default and
      rejects either with `display_text_oversized` under
      `rejectOversizedDisplayText`, with `details.userNoticeField` naming the
      field; PKITS §4.8.19 leaves that choice for `explicitText` to the
      application. The 200-character bound and the [RFC 6818 §3][rfc6818-section-3] rules for
      conforming CAs (no IA5String, no control characters, NFC) bind the
      builder.
- [x] Support `policyConstraints`.
- [x] Support `policyMappings`.
- [x] Support `inhibitAnyPolicy`.
- [x] Use the **[RFC 9618][rfc9618]** update rather than the older [RFC 5280][rfc5280] policy-tree
      algorithm, because [RFC 9618][rfc9618] replaced it with an equivalent, more efficient
      algorithm to avoid worst-case exponential blowups and DoS risk.
      (IETF Datatracker[^rfc9618])
- [x] Conformance evidence landed: the full PKITS policy sections (4.8–4.12)
      pass, with every manifest expectation verified against the official
      PKITS document ([`docs/rfc/pkits.txt`](./rfc/pkits.txt)). 4.8.19, whose
      explicitText is 310 characters, validates under the default settings as
      the manifest expects; the harness also checks that the notice is kept
      whole and reported, that `rejectOversizedDisplayText` rejects the path
      for that reason alone, and that the other user-notice tests validate
      under it.

## 7. Trust-anchor model

- [x] Accept trust anchors as structured input, not only as “root cert PEM”.
- [x] Allow trust anchor info to come from a self-signed certificate as a
      convenience, but treat the trust anchor as out-of-band trust input.
- [x] Do not assume every self-signed cert is a trust anchor.
      (IETF Datatracker[^rfc5280])

## 8. Application/service identity checks

- [x] Keep hostname/service-name matching in a separate API from path validation.
- [x] For each supported identity type (`dNSName`, `iPAddress`, URI-ID, SRV-ID), match `subjectAltName` entries of the corresponding type first.
- [x] `matchServiceIdentity()` supports `dNSName`, `iPAddress`, URI-ID, and SRV-ID matching with wildcard and IDNA coverage.
- [x] Verification helpers (`verifyCertificateChain`, `validateForTlsServer`, …) accept the same identity union as `matchServiceIdentity()`.
- [x] Only support CN fallback as an explicit [RFC 6125][rfc6125] compatibility mode; [RFC 9525][rfc9525] forbids using the Common Name RDN to identify a service. (IETF Datatracker[^rfc6125], [^rfc9525])
- [x] Make wildcard behavior explicit and test it hard.
- [x] Match a presented wildcard in a URI-ID or SRV-ID as [RFC 9525 §6.3][rfc9525-section-6.3] does
      in the DNS domain name portion: one `*` forming the whole left-most
      label, matching exactly one label. A wildcard placed anywhere else makes
      the identifier invalid and it is ignored. A `sip` or `sips` URI-ID takes
      no wildcard ([RFC 5922 §7.2][rfc5922-section-7.2]), and a reference identifier holds none.
- [x] Take a URI-ID's host as §7 reads a URI SAN's host. A `sip` or `sips`
      URI has no [RFC 3986][rfc3986] authority, so its host comes from the [RFC 3261
      §25.1][rfc3261-section-25.1] hostport, as [RFC 9525 §6.2][rfc9525-section-6.2] splits `sip:voice.college.example`.
      [§25.1][rfc3261-section-25.1] puts the userinfo and hostport right after the scheme, so a `//`
      there makes the URI-ID invalid. The hostport follows the one "@" [§25.1][rfc3261-section-25.1]
      allows, which ends a userinfo of a non-empty user and an optional
      password, and ends at the first ";" or "?". The user part may hold "?",
      "/" and ";". A second "@", a user or password outside the [§25.1][rfc3261-section-25.1]
      grammar, a "/" or escaped octet in the hostport, a host that is neither
      a [§25.1][rfc3261-section-25.1] hostname nor an IP address, or a ":" with no port digits after
      it makes the URI-ID invalid. So do uri-parameters or headers outside
      their [§25.1][rfc3261-section-25.1] grammar and a parameter name that appears twice, compared
      without regard to case ([§19.1.1][rfc3261-section-19.1.1], [§19.1.4][rfc3261-section-19.1.4]). Every "%" opens an escaped
      octet, as the [RFC 2396][rfc2396] rules [§19.1.2][rfc3261-section-19.1.2] adopts require, although the
      `token` production admits a raw "%". A presented SIP URI with a
      userinfo identifies a user, and [RFC 5922 §7.1][rfc5922-section-7.1] forbids accepting it as a
      SIP domain identity, so it matches nothing. A reference identifier may
      carry one, and only its host is compared ([RFC 5922 §7.3][rfc5922-section-7.3], [RFC 9525
      §6.1.1][rfc9525-section-6.1.1]). An IP host matches by its octets ([RFC 9525 §6.4][rfc9525-section-6.4]).
- [x] Hold an SRV-ID, presented or reference, to the SRVName syntax of §7.

Focused [RFC 9525][rfc9525] identity fixtures live in [`test/identity-fixtures.test.ts`](../test/identity-fixtures.test.ts).

## 9. EKU / purpose checks

- [x] Keep EKU checks separate from raw path validity.
- [x] Allow callers to request purposes such as `serverAuth`, `clientAuth`, etc.
- [x] Distinguish “certificate is path-valid” from “certificate is acceptable for this application”.

## 10. OCSP support checklist

- [x] Build `CertID` from issuer name hash, issuer key hash, serial number, and hash algorithm.
- [x] Discover the responder from AIA `id-ad-ocsp` or let callers provide a responder URL explicitly.
- [x] Parse and verify `BasicOCSPResponse`.
- [x] Check that the response fully and correctly refers to the requested certificate set.
- [x] Validate the OCSP response signature.
- [x] Validate responder authorization exhaustively.
  - [x] Land [RFC 6960 §4.2.2.2][rfc6960-section-4.2.2.2] criterion 1: explicit local signer acceptance scoped to the issuing CA
        (`trustedOcspResponders` on `validateOcspResponse()`, `trustedOcspResponders` on chain orchestration).
  - [x] Decide and enforce responder-certificate revocation policy — see §11 for the canonical breakdown.
  - [x] Add fixture coverage for configured-responder accept/reject and historical-time validation.
- [x] Enforce response freshness using `thisUpdate` / `nextUpdate` and configurable clock skew.
      By default a response without `nextUpdate` is accepted, as [RFC 6960
      §4.2.2.1][rfc6960-section-4.2.2.1] allows. The opt-in [RFC 9919][rfc9919] client profile
      (`profile: 'rfc9919'` on `validateOcspResponse`,
      `ocspProfile: 'rfc9919'` on `checkCertificateRevocation` and the chain
      `RevocationPolicy`) rejects it with `next_update_missing`, or
      `ocsp_next_update_missing` on the chain ([RFC 9919 §5][rfc9919-section-5]).
- [x] Return `good`, `revoked`, and `unknown` distinctly.
- [x] Support optional nonce handling if you want replay binding between request and response. [RFC 9654][rfc9654] defines the updated nonce extension details. (IETF Datatracker[^rfc6960])
- [x] Consume caller-supplied OCSP responses in chain-level revocation
      orchestration (`checkChainRevocation()` / `verifyCertificateChain()`),
      with fail-closed combination against CRL evidence: a validated
      `revoked` verdict from either source always wins; when both validate
      as `good`, the default `'best-available'` preference reports the
      source with the fresher `thisUpdate` (an applied delta CRL counts as
      its own `thisUpdate`; ties favor OCSP), surfaced as
      `source.thisUpdate` on the per-certificate status.

## 11. OCSP responder authorization rules

- [x] Accept an OCSP response signer if it matches local responder configuration for the certificate in question.
  - [x] Add a validation input binding trusted responder certs to issuer CA scopes
        (`trustedOcspResponders` — per-call, and each call is scoped to one issuer).
  - [x] Thread local responder policy through `validateOcspResponse()` before falling back to issuer-cert or delegated-responder rules.
  - [x] Add positive and negative fixtures for locally authorized signer scope.
- [x] Accept it if the signer is the issuing CA certificate itself.
- [x] Accept it if the signer cert contains EKU `id-kp-OCSPSigning` **and** was issued directly by the CA that issued the target certificate.
- [x] Reject the response if the signer certificate meets none of those conditions.
- [x] Decide and document responder-certificate revocation policy ([RFC 6960 §4.2.2.2.1][rfc6960-section-4.2.2.2.1]).
  - [x] Parse and expose `id-pkix-ocsp-nocheck` (`hasOcspNoCheckExtension()`).
  - [x] Define validator policy knobs: `responderRevocationPolicy` = `'honor-nocheck'` (default) / `'require-evidence'` / `'skip'`, with `responderRevocationCrls` as evidence and `trustedOcspResponders` as the caller-local override.
  - [x] Add fixtures for each policy branch.
  - [x] Pass caller evaluation time through delegated responder chain validation.

Focused OCSP auth/completeness/freshness fixtures live in [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts).

## 12. CRL support checklist

- [x] Treat CRL validation as a separate revocation subsystem.
- [x] Parse CRLs and CRL extensions.
- [x] Verify CRL signatures and issuer linkage.
- [x] Skip chain-level revocation checking for a certificate carrying
      `noRevAvail` or `id-pkix-ocsp-nocheck`, and reject a certificate pairing
      `noRevAvail` with cA TRUE, cRLDistributionPoints, freshestCRL or an
      `id-ad-ocsp` authorityInfoAccess entry ([RFC 9608 §3][rfc9608-section-3], [§4][rfc9608-section-4]).
- [x] Require keyUsage with `cRLSign` on a v3 CRL issuer certificate, and skip
      the check for v1 and v2 issuers ([RFC 10007 §4][rfc10007-section-4], updating [RFC 5280 §6.3.3][rfc5280-section-6.3.3]
      step (f)).
- [x] Enforce CRL time/freshness semantics. CRL age is unbounded by default,
      and a received CRL without `nextUpdate` fails with `stale_crl` unless the
      caller sets `maxAgeMs` (`validateCertificateRevocationList`,
      `checkCertificateRevocationAgainstCrl`), `crlMaxAgeMs`
      (`checkCertificateRevocation`, the chain `RevocationPolicy`) or
      `responderRevocationCrlMaxAgeMs` (`validateOcspResponse`), which then
      governs it. [RFC 5280 §5.1.2.5][rfc5280-section-5.1.2.5] does not specify client behaviour for
      such a CRL, and [§3.3][rfc5280-section-3.3] leaves the required recency of revocation data to
      local policy.
- [x] Always encode `nextUpdate` in generated CRLs ([RFC 5280 §5.1.2.5][rfc5280-section-5.1.2.5]).
      `createCertificateRevocationList` also requires it at least one second
      after `thisUpdate`. This is a micro509 builder invariant. [RFC 5280][rfc5280] and
      X.509 do not specify an order between the two fields.
- [x] Always encode the Authority Key Identifier, by the key identifier method,
      and a non-critical CRL Number in generated CRLs ([RFC 5280 §5.2.1][rfc5280-section-5.2.1],
      [§5.2.3][rfc5280-section-5.2.3]). `createCertificateRevocationList` requires `issuerPublicKey`
      and `crlNumber`, and refuses a CRL number or base CRL number longer than 20
      octets. Parsing reads CRL numbers of any length as `bigint`, since verifiers
      must handle values up to 20 octets.
- [x] Refuse a CRL whose revoked entry carries a critical extension other
      than reasonCode, invalidityDate or certificateIssuer
      ([RFC 5280 §5.3][rfc5280-section-5.3]).
- [x] Keep a CRLReason outside [RFC 5280 §5.3.1][rfc5280-section-5.3.1] as
      `{ type: 'unrecognized', code }`, including X.509's
      `weakAlgorithmOrKey (11)`. Neither [RFC 5280][rfc5280] nor X.509 says what a
      relying party does with such a code, so `unrecognizedReasonCode` on
      `checkCertificateRevocationAgainstCrl`, `checkCertificateRevocation` and
      the chain `RevocationPolicy` (`responderRevocationUnrecognizedReasonCode`
      on `validateOcspResponse`) chooses: `'revoked'` (default) or `'reject'`,
      under which the evidence settles nothing and other evidence cannot
      settle the status as `good`. The same holds for a CRL signer or a
      delegated OCSP responder listed with such a code. Codes decode as
      `bigint` at any length. A critical cRLReason holding an
      unrecognized code makes the CRL malformed ([RFC 5280 Appendix B][rfc5280-appendix-B]).
- [x] Parse CRL distribution points and enforce distribution-point scope during
      CRL applicability; CRL discovery/fetch hooks are not shipped.
- [x] Add delta CRL handling only if you actually want to live in that swamp. [RFC 5280][rfc5280] defines CRL validation separately from path validation. (IETF Datatracker[^rfc5280])
      Chain evaluation uses only a current delta CRL whose CRL number exceeds
      the base CRL's ([RFC 5280 §5.2.4][rfc5280-section-5.2.4]), and it tries candidates from the
      latest `thisUpdate` down ([RFC 5280 §5.2.4][rfc5280-section-5.2.4]). A candidate that fails
      authentication, freshness, compatibility or applicability is skipped,
      and the base CRL is evaluated alone once every candidate is skipped. A
      candidate that passes those checks is used, and when its revoked entries
      cannot settle the certificate's status the result is indeterminate with
      `delta_crl_unusable`. At most four candidates are checked per base CRL
      and 32 per `checkChainRevocation` call. A base CRL that does not cover
      the certificate spends none, and repeated copies of one base or delta
      CRL count once. Pre-parsed CRLs are read from their `der`. A candidate
      left unchecked makes the result indeterminate with
      `delta_crl_retry_limit_exceeded`. Both reasons outrank a `good` verdict from other evidence. Neither
      replaces a base CRL revocation that no delta can remove: one with a
      reason other than `certificateHold`, for a certificate that has not
      expired at the evaluation time ([RFC 5280 §5.3.1][rfc5280-section-5.3.1]). Beside an unusable
      delta, the base CRL needs no freshness of its own, as with any delta;
      beside unexamined candidates, it must be fresh. These are micro509
      policy choices. It also requires the delta's
      `thisUpdate` to be no earlier than the base CRL's, because X.509 Annex
      E.5.2 requires a delta CRL to be issued after the base CRL it updates.
      X.509 does not say whether an equal `thisUpdate` meets that rule, and
      micro509 accepts it. `checkCertificateRevocationAgainstCrl` reports
      `delta_crl_incompatible` for a delta whose `thisUpdate` precedes the
      complete CRL's (X.509 Annex E.5.2).

## 13. API design checklist

- [x] Keep path building separate from path validation.
- [x] Keep service identity matching in a separate API from path validation.
- [x] Keep revocation checking separate from path validation.
- [x] Expose structured validation inputs instead of hiding policy/name-constraint knobs.
- [x] Return typed failure reasons for currently implemented path-validation, CRL, and OCSP checks.
- [x] Distinguish hard validation failure from revocation status `unknown` in
      revocation orchestration; chain, CRL, and OCSP validators still return
      binary success/failure results.

## 14. Test/conformance checklist

- [x] Add fixed RFC-style test vectors for builders, parsers, and validators.
- [x] Add round-trip tests for certs, CSRs, names, and extensions.
- [x] Run the full NIST PKITS suite: all 224 test procedures across sections
      4.1–4.16, expanded to 249 runs including every documented subtest
      variation; manifest expectations verified against the official PKITS
      document ([`docs/rfc/pkits.txt`](./rfc/pkits.txt)). 4.1.4/4.1.5 (DSA)
      are expected-fail per the WebCrypto algorithm boundary and tracked with
      `it.failing`. See [`test/pkits.test.ts`](../test/pkits.test.ts).
- [x] Add malformed DER / fuzz tests.
- [x] Differential-test against at least one mature implementation. See [`test/differential.test.ts`](../test/differential.test.ts).
- [x] Run the validator against **NIST PKITS** as a gap-report harness, which NIST describes as a comprehensive X.509 path validation test suite for relying parties. (NIST Computer Security Resource Center[^x-509-path-validation])

## 15. PKCS#12 and PBES2 boundary

- [x] Accept BER for the PFX, the authSafe ContentInfo, the AuthenticatedSafe
      and each SafeContents in `parsePfxDer` / `parsePfxPem`: indefinite
      lengths, non-minimal lengths and constructed OCTET STRINGs ([RFC 7292 §4][rfc7292-section-4];
      X.690 §7.3). BER nesting is limited to 64 levels (`limit_exceeded`).
      Certificate and PKCS#8 bag payloads must be DER. The MAC is verified over the AuthenticatedSafe
      octets as received ([RFC 7292 Appendix A][rfc7292-appendix-A]).
- [x] Verify and create the [RFC 7292][rfc7292] MAC with SHA-256 only. Any other digest
      returns `unsupported_mac_algorithm`.
- [x] Require the [RFC 7292][rfc7292] MAC password to be a BMPString ([RFC 7292
      Appendix B.1][rfc7292-appendix-B.1]). A password containing a UTF-16 surrogate, from a non-BMP
      character or a lone surrogate, is rejected with
      `password_not_bmp_string`. [RFC 7292][rfc7292] does not specify this case, so the
      rejection is micro509 policy. X.680 §41.15 leaves U+FFFE and U+FFFF out
      of BMPString, and a password holding either gets the same code.
- [x] Hold a bag's friendlyName to [RFC 2985 §5.5.1][rfc2985-page-17], which [RFC 7292][rfc7292] imports:
      one value, a BMPString of 1 to 255 characters from the BMPString
      repertoire (X.680 §41.15), so no surrogate code unit, U+FFFE or U+FFFF.
      `createPfx` throws `invalid_friendly_name` for any other name, and
      parsing returns `malformed` for any other value. Rejecting a second
      friendlyName attribute in one bag is micro509 policy.
- [x] Reject MacData iterations of 0 or below as `malformed`. [RFC 7292 §4][rfc7292-section-4]
      gives the field no range, so this is micro509 policy.
- [x] Verify [RFC 9879][rfc9879] PBMAC1 with PBKDF2 and an HMAC-SHA-256, HMAC-SHA-384 or
      HMAC-SHA-512 PRF and MAC. PBKDF2 params must carry `keyLength`, and a
      `keyLength` below 20 octets returns `weak_mac_key_length`. The password
      is encoded as UTF-8 with no NULL terminator or BOM. MacData `iterations`
      and `macSalt` are ignored.
- [x] Create PBMAC1 only on request with `mac: { type: 'pbmac1' }`
      (PBKDF2-HMAC-SHA-256, a 32-octet key, HMAC-SHA-256). The default MAC is
      the [RFC 7292][rfc7292] SHA-256 MAC.
- [x] Cap the PBKDF2 `iterationCount` at 4294967295, the largest value
      WebCrypto's `[EnforceRange] unsigned long` accepts. [RFC 8018][rfc8018] §A.2
      leaves the maximum iteration count to the implementation. A larger
      PBES2 or PBMAC1 count is `malformed`. The PBES2 encoders throw `RangeError`,
      and PBMAC1 creation throws `invalid_iterations`.

[^rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280 "RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"

[^rfc5480]: https://datatracker.ietf.org/doc/html/rfc5480 "RFC 5480 - Elliptic Curve Cryptography Subject Public Key Information"

[^rfc9618]: https://datatracker.ietf.org/doc/html/rfc9618 "RFC 9618 - Updates to X.509 Policy Validation"

[^rfc6125]: https://datatracker.ietf.org/doc/html/rfc6125 "RFC 6125 - Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)"

[^rfc9525]: https://datatracker.ietf.org/doc/html/rfc9525 "RFC 9525 - Service Identity in TLS"

[^rfc6960]: https://datatracker.ietf.org/doc/html/rfc6960 "RFC 6960 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP"

[^x-509-path-validation]: https://csrc.nist.gov/projects/pki-testing/x-509-path-validation-test-suite "X.509 Path Validation Test Suite - Public Key Infrastructure Testing | CSRC"

[eid5997]: https://www.rfc-editor.org/errata/eid5997
[rfc1345]: https://www.rfc-editor.org/rfc/rfc1345.html
[rfc1421]: https://www.rfc-editor.org/rfc/rfc1421.html
[rfc2396]: https://www.rfc-editor.org/rfc/rfc2396.html
[rfc2782]: https://www.rfc-editor.org/rfc/rfc2782.html
[rfc2985-page-17]: https://www.rfc-editor.org/rfc/rfc2985.html#page-17
[rfc3261-section-19.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.1
[rfc3261-section-19.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.2
[rfc3261-section-19.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.4
[rfc3261-section-25.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1
[rfc3490]: https://www.rfc-editor.org/rfc/rfc3490.html
[rfc3490-section-2]: https://www.rfc-editor.org/rfc/rfc3490.html#section-2
[rfc3490-section-3.1]: https://www.rfc-editor.org/rfc/rfc3490.html#section-3.1
[rfc3490-section-4]: https://www.rfc-editor.org/rfc/rfc3490.html#section-4
[rfc3986]: https://www.rfc-editor.org/rfc/rfc3986.html
[rfc3986-section-2.3]: https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3
[rfc3986-section-3.2.1]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1
[rfc3986-section-3.2.2]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2
[rfc3986-section-3.3]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3
[rfc3986-section-3.5]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5
[rfc3986-section-6]: https://www.rfc-editor.org/rfc/rfc3986.html#section-6
[rfc3986-section-6.2.2.2]: https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.2
[rfc3987-section-2.2]: https://www.rfc-editor.org/rfc/rfc3987.html#section-2.2
[rfc3987-section-4.1]: https://www.rfc-editor.org/rfc/rfc3987.html#section-4.1
[rfc4518]: https://www.rfc-editor.org/rfc/rfc4518.html
[rfc4518-section-2]: https://www.rfc-editor.org/rfc/rfc4518.html#section-2
[rfc4518-section-2.1]: https://www.rfc-editor.org/rfc/rfc4518.html#section-2.1
[rfc4648-section-3.5]: https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5
[rfc4985]: https://www.rfc-editor.org/rfc/rfc4985.html
[rfc4985-section-2]: https://www.rfc-editor.org/rfc/rfc4985.html#section-2
[rfc4985-section-3]: https://www.rfc-editor.org/rfc/rfc4985.html#section-3
[rfc4985-section-4]: https://www.rfc-editor.org/rfc/rfc4985.html#section-4
[rfc5280]: https://www.rfc-editor.org/rfc/rfc5280.html
[rfc5280-appendix-A.1]: https://www.rfc-editor.org/rfc/rfc5280.html#appendix-A.1
[rfc5280-appendix-B]: https://www.rfc-editor.org/rfc/rfc5280.html#appendix-B
[rfc5280-section-3.3]: https://www.rfc-editor.org/rfc/rfc5280.html#section-3.3
[rfc5280-section-4.2]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2
[rfc5280-section-4.2.1.4]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
[rfc5280-section-4.2.1.10]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10
[rfc5280-section-5.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.5
[rfc5280-section-5.2.1]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.1
[rfc5280-section-5.2.3]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
[rfc5280-section-5.2.4]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.4
[rfc5280-section-5.3]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3
[rfc5280-section-5.3.1]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3.1
[rfc5280-section-6.3.3]: https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3.3
[rfc5280-section-7.1]: https://www.rfc-editor.org/rfc/rfc5280.html#section-7.1
[rfc5280-section-7.4]: https://www.rfc-editor.org/rfc/rfc5280.html#section-7.4
[rfc5652]: https://www.rfc-editor.org/rfc/rfc5652.html
[rfc5890]: https://www.rfc-editor.org/rfc/rfc5890.html
[rfc5891]: https://www.rfc-editor.org/rfc/rfc5891.html
[rfc5891-section-4]: https://www.rfc-editor.org/rfc/rfc5891.html#section-4
[rfc5891-section-5]: https://www.rfc-editor.org/rfc/rfc5891.html#section-5
[rfc5895]: https://www.rfc-editor.org/rfc/rfc5895.html
[rfc5922-section-7.1]: https://www.rfc-editor.org/rfc/rfc5922.html#section-7.1
[rfc5922-section-7.2]: https://www.rfc-editor.org/rfc/rfc5922.html#section-7.2
[rfc5922-section-7.3]: https://www.rfc-editor.org/rfc/rfc5922.html#section-7.3
[rfc6125]: https://www.rfc-editor.org/rfc/rfc6125.html
[rfc6335-section-5.1]: https://www.rfc-editor.org/rfc/rfc6335.html#section-5.1
[rfc6335-section-5.2]: https://www.rfc-editor.org/rfc/rfc6335.html#section-5.2
[rfc6818-section-3]: https://www.rfc-editor.org/rfc/rfc6818.html#section-3
[rfc6960]: https://www.rfc-editor.org/rfc/rfc6960.html
[rfc6960-section-4.2.2.1]: https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.1
[rfc6960-section-4.2.2.2]: https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.2
[rfc6960-section-4.2.2.2.1]: https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.2.1
[rfc7292]: https://www.rfc-editor.org/rfc/rfc7292.html
[rfc7292-appendix-A]: https://www.rfc-editor.org/rfc/rfc7292.html#appendix-A
[rfc7292-appendix-B.1]: https://www.rfc-editor.org/rfc/rfc7292.html#appendix-B.1
[rfc7292-section-4]: https://www.rfc-editor.org/rfc/rfc7292.html#section-4
[rfc7468]: https://www.rfc-editor.org/rfc/rfc7468.html
[rfc8018]: https://www.rfc-editor.org/rfc/rfc8018.html
[rfc8410]: https://www.rfc-editor.org/rfc/rfc8410.html
[rfc8753]: https://www.rfc-editor.org/rfc/rfc8753.html
[rfc9295]: https://www.rfc-editor.org/rfc/rfc9295.html
[rfc9295-section-3]: https://www.rfc-editor.org/rfc/rfc9295.html#section-3
[rfc9525]: https://www.rfc-editor.org/rfc/rfc9525.html
[rfc9525-section-2]: https://www.rfc-editor.org/rfc/rfc9525.html#section-2
[rfc9525-section-6.1.1]: https://www.rfc-editor.org/rfc/rfc9525.html#section-6.1.1
[rfc9525-section-6.2]: https://www.rfc-editor.org/rfc/rfc9525.html#section-6.2
[rfc9525-section-6.3]: https://www.rfc-editor.org/rfc/rfc9525.html#section-6.3
[rfc9525-section-6.4]: https://www.rfc-editor.org/rfc/rfc9525.html#section-6.4
[rfc9549]: https://www.rfc-editor.org/rfc/rfc9549.html
[rfc9549-section-2.2]: https://www.rfc-editor.org/rfc/rfc9549.html#section-2.2
[rfc9598-section-6]: https://www.rfc-editor.org/rfc/rfc9598.html#section-6
[rfc9608-section-3]: https://www.rfc-editor.org/rfc/rfc9608.html#section-3
[rfc9608-section-4]: https://www.rfc-editor.org/rfc/rfc9608.html#section-4
[rfc9618]: https://www.rfc-editor.org/rfc/rfc9618.html
[rfc9618-section-5.1]: https://www.rfc-editor.org/rfc/rfc9618.html#section-5.1
[rfc9618-section-5.5]: https://www.rfc-editor.org/rfc/rfc9618.html#section-5.5
[rfc9654]: https://www.rfc-editor.org/rfc/rfc9654.html
[rfc9879]: https://www.rfc-editor.org/rfc/rfc9879.html
[rfc9919]: https://www.rfc-editor.org/rfc/rfc9919.html
[rfc9919-section-3.1.1]: https://www.rfc-editor.org/rfc/rfc9919.html#section-3.1.1
[rfc9919-section-5]: https://www.rfc-editor.org/rfc/rfc9919.html#section-5
[rfc10007-section-4]: https://www.rfc-editor.org/rfc/rfc10007.html#section-4

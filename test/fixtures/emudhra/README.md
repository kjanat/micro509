# eMudhra certificate incident fixtures

These offline fixtures preserve evidence published for the eMudhra intermediate
CA incident. They are public certificates and CRLs; no private keys are present.

## Primary sources and SHA-256

| Fixture                                             | Source                                                                                                         | SHA-256                                                            |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `chains.zip`                                        | [Published chain archive](https://emudhra.we-have-a-problem.com/chains.zip)                                    | `7b949956955fc501a30f4d98d2f513d34c0bbbe92e29a968194c96e097ce2345` |
| `impacted-intermediates.json`                       | [Published impacted intermediates](https://emudhra.we-have-a-problem.com/impacted-intermediates.json)          | `b477a727fe6c033b7035ef033f114ab3277b6eb0f2f352a06449e2cb735a9bb2` |
| `dv-g3b-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `ab6483de0cb01d53d59275baf74d2766f3599e57a48d3319e4a5536c268ac696` |
| `dv-g3b-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `3641ff8e872e4c90d5691edb09894914121b267e6a50455347c5f28708fa1af2` |
| `ov-g3b-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `c80265d7a38b7378544488d35c317598d5d8b9a1444468f68aa96b134d561d0b` |
| `ov-g3b-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `402cc78d8effe1157b92fbe23ffdb860a6ac754bd126692f98d4b1d2df66e35d` |
| `ev-g3b-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `000c2f6b03a9903488ee18e09c6b86e22c2476d0052e11888e5f924de6ad0d44` |
| `ev-g3b-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `19fcef2a9fa3ecc88294736d1bdcc2cd7c8753960ff67e8890affa13bd5ea4e5` |
| `dv-g3b-noct-emudhra.we-have-a-problem.com.pem`     | Extracted unchanged from `chains.zip`                                                                          | `de597b4e346d6e84d264a6bc62f5cb5bf4a4d64ec5e587edc446016e4aa693c5` |
| `dv-g3b-aaa-noct-emudhra.we-have-a-problem.com.pem` | Extracted unchanged from `chains.zip`                                                                          | `a360266958b7dfc04250553f6a5f55be769457f126bfd4de415bbaffc9cf62ad` |
| `dv-g3c-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `370e97ac882a900d25bda5b8ffe0136197e41d1ab424c3f04adad77825283803` |
| `dv-g3c-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `23641e6de1b0c5a452bd0aaaaa1647863cf5daf27e0b62611ea9289dc0106d39` |
| `ov-g3c-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `45e16413868da62601227eb792c9d8a2172f0765fde3e7f21524e188bd3a1f41` |
| `ov-g3c-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `4cf2e52ff28f08d690046a75def341abf6508d18c197c6825c7820e0899e1c63` |
| `ev-g3c-emudhra.we-have-a-problem.com.pem`          | Extracted unchanged from `chains.zip`                                                                          | `636f60b161812118b0474d5fdc1e194aaa1913ebc06331e0f24b324f08ba9a73` |
| `ev-g3c-aaa-emudhra.we-have-a-problem.com.pem`      | Extracted unchanged from `chains.zip`                                                                          | `6a3019bee019f96570bffca9002637655e7fa8221a370021ca6e0b0fd66f576d` |
| `aaa-certificate-services-root.crt`                 | [Sectigo published root](http://crt.sectigo.com/AAACertificateServices.crt)                                    | `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4` |
| `emsign-root-tls-g3.crl`                            | CRL URL in the impacted-intermediates listing: `http://crl.emsign.com/?roottlscag3.crl` (retrieved over HTTPS) | `3fca75a8b774172c92af79c9023e782c1eade468c44965de06e9ebdea91c6a2b` |
| `aaa-certificate-services.crl`                      | CRL URL in the impacted-intermediates listing: `http://crl.comodoca.com/AAACertificateServices.crl`            | `be9a0c0064db1133e67eb809b9efdd5d0c91844283a0e44280a0091f3679ad08` |

The JSON inventory is formatted with dprint. Its downloaded SHA-256 was
`f67b3abe9b4879f4e91874ed041beccd71257f1db41c588c724ccf12aa90c59e`. The table records the
formatted file hash. Certificate and CRL bytes are copied verbatim.

The upstream archive README says its chains were captured on 20 October 2026
and the two `noct` chains on 22 October 2026. The 14 TLS chain files are copied
verbatim from that archive: original eMudhra and AAA Certificate Services
cross-signed paths for DV G3B, DV G3B no-CT, DV G3C, OV G3B, OV G3C, EV G3B,
and EV G3C.

The two CRLs are DER encoded. The eMudhra CRL reports `lastUpdate` 2026-10-18
09:38:46 UTC and `nextUpdate` 2027-04-16 09:38:46 UTC. The Sectigo CRL reports
`lastUpdate` 2026-10-23 17:39:56 UTC and `nextUpdate` 2026-10-30 17:39:56 UTC.
The checks use the fixed evaluation time `2026-10-23T20:00:00Z`; the time is
inside both CRLs' validity windows and after the published revocation times.

## Coverage

`test/emudhra.test.ts` checks that each original/cross-signed intermediate pair
has the published SPKI SHA-256 fingerprint, verifies each intended chain, and
tests mixed issuer and root candidate ordering against the SPKI denylist. Both
issuer CRLs identify each included intermediate as revoked. The suite checks
revocation on the intermediate-only path and on the full leaf chain, where the
revoked intermediate must be reported at index 1 despite missing leaf evidence.
Tests load only local fixture files and make no network requests.

The verification guide serves byte-identical copies of the two DV G3B chain
files and the AAA Certificate Services root from `site/assets/fixtures/emudhra/`.
Its LiveCode example uses those local assets at the same fixed evaluation time.

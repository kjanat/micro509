---
source: https://csrc.nist.gov/projects/pki-testing
notes: Created May 24, 2016, Updated March 31, 2025
---

# Public Key Infrastructure Testing | CSRC

> ## Excerpt
>
> Testing PKI Components NIST/Information Technology Laboratory responds to industry and user needs for objective, neutral tests for information technology. ITL recognizes such tests as the enabling tools that help companies produce the next generation of products and services. It is a goal of the NIST PKI Program to develop such tests to help companies produce interoperable PKI components. NIST worked with CygnaCom Solutions and BAE Systems to develop a suite of tests that will enable developers and validation laboratories to determine a PKI client application's conformance to the path processing rules as specified in X.509.  Path Validation Testing Program The Public Key Interoperability Test Suite (PKITS) is a comprehensive X.509 path validation test suite that was developed by NIST in conjunction with BAE Systems and NSA.  The PKITS path validation test suite is designed to cover most of the features specified in X.509 and RFC 3280. Both test descriptions and test data are available for the PKITS path...

---

### Testing PKI Components

NIST/Information Technology Laboratory responds to industry and user needs for objective, neutral tests for information technology. ITL recognizes such tests as the enabling tools that help companies produce the next generation of products and services. It is a goal of the NIST PKI Program to develop such tests to help companies produce interoperable PKI components.

NIST worked with CygnaCom Solutions and BAE Systems to develop a suite of tests that will enable developers and validation laboratories to determine a PKI client application's conformance to the path processing rules as specified in X.509.

### Path Validation Testing Program

The Public Key Interoperability Test Suite (PKITS) is a comprehensive X.509 path validation test suite that was developed by NIST in conjunction with BAE Systems and NSA.  The PKITS path validation test suite is designed to cover most of the features specified in X.509 and [RFC 3280](https://doi.org/10.17487/RFC3280).

Both test descriptions and test data are available for the PKITS path validation test suite:

- [Test descriptions](https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf) - a PDF file containing descriptions of the tests in the test suite.
- [Test data](https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip) - a zip file containing all of the data needed to run the tests. This includes all of the certificates and CRLs used in the tests, PKCS #12 files containing the private keys of each end-entity (the password for each PKCS #12 file is "password"), signed [S/MIME](http://www.ietf.org/rfc/rfc5751.txt) messages for each test, and an [LDIF](http://www.ietf.org/rfc/rfc2849.txt) file that can be used to populate a directory with all of the certificates and CRLs used in the tests. The certificates and CRLs used in the test suite are also available in an LDAP directory (smime2.nist.gov).
- (PKITS version 1.0.1 was posted on April 14, 2011. The [test descriptions](https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_v1_0_0.pdf) and [test data](https://csrc.nist.gov/CSRC/media/Projects/PKI-Research-and-Testing/documents/PKITS_data_v1_0_0.zip) for PKITS version 1.0 will remain available for those wish to continue to use the original version of the test suite.)

PKITS supersedes an earlier path validation test suite, [Conformance Testing of Relying Party Client Certificate Path Processing Logic](https://csrc.nist.gov/projects/pki-testing/x-509-path-validation-test-suite).  PKITS incorporates all of the tests from the earlier test suite, but also includes tests for many features that were not covered by the earlier test suite.

### Path Discovery Testing Program

The path discovery test suite consists of a set of sample PKI architectures.  In each PKI architecture one CA is designated as the trust anchor and several end-entity certificates have been issued.  Each test involves either locating all of the intermediate certificates and CRLs needed to validate an end-entity certificate or determining that no valid certification path exists.

Both test descriptions and test data are available for the path discovery test suite:

- [Test descriptions](https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.pdf) - a PDF file containing descriptions of the tests in the test suite.
- [Test data](https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PathDiscoveryTestSuite.zip) - a zip file containing all of the data needed to run the tests. This includes all of the end-entity certificates used in the tests, PKCS #12 files containing the private keys of each end-entity (the password for each PKCS #12 file is "password"), signed [S/MIME](http://www.ietf.org/rfc/rfc2633.txt) messages for each test, and a self-signed certificate for each of the trust anchors. The intermediate certificates and CRLs for the Directory based path discovery tests are available via LDAP at smime2.nist.gov.

The initial draft of the test suite contains three PKI architectures.  The three PKI architectures are all very similar, the main difference being the method by which intermediate certificates and CRLs may be located.  In one architecture, the certificates include LDAP URIs that indicate where certificates and CRLs may be found.  In another architecture, the certificates include HTTP URIs that indicate where certificates and CRLs may be found.  In the third architecture, the certificates do not include any information indicating where certificates and CRLS may be found, but the certificates and CRLs may be obtained from smime2.nist.gov using LDAP as specified in [RFC 2587](https://doi.org/10.17487/RFC2587).

Each of the PKI architectures is designed to test a path discovery and validation module's abilities to perform path discovery at two different levels of complexity.  At the Rudimentary level, all end-entity certificates are issued by CAs that are hierarchically subordinate to the trust anchor CA.  At the Basic level, end-entity certificates are issued by CAs that are connected to the trust anchor CA by a mesh PKI architecture.  Path discovery and validation modules that are capable of discovering and validating all of the certification paths at the Rudimentary and Basic levels within the Directory based PKI architecture should be capable of discovering certification paths within the Federal PKI as it is currently constructed.

The path discovery test suite is intended for use with path discovery and validation modules whose path validation capabilities have already been successfully tested using PKITS. The Rudimentary path discovery tests require a path validation module that implements the basic path validation functionality along with support for a few certificate extensions (key usage, basic constraints, and certificate policies). The Basic path discovery tests additionally require the path validation module to support processing name constraints for the directoryName name form, the policyMappings extension, the inhibitPolicyMapping field of the policyConstraints extension, and certificatePolicies extensions that assert the anyPolicy OID.

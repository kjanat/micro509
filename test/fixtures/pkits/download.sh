#!/usr/bin/env bash

# Copyright 2026 The micro509 Authors
#
# This script downloads the certificates used in the PKITS test suite from the
# BoringSSL repository. (`google/boringssl` on github.com, apache 2.0 licensed).
#
# The PKITS test suite is a collection of test cases for validating X.509
# certificate path validation implementations against the NIST PKITS test cases.

# Ensure we're at repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "Error: Not in a git repository." >&2
	exit 1
}

CERT_DIR="${REPO_ROOT}/test/fixtures/pkits/certs"
cd "${REPO_ROOT}" || {
	echo "Error: Could not change to repo root." >&2
	exit 1
}

mkdir -p "${CERT_DIR}" || {
	echo "Error: Could not create cert directory." >&2
	exit 1
}

files=(
	GoodCACert InvalidDNandRFC822nameConstraintsTest28EE InvalidpathLenConstraintTest5EE
	P12Mapping1to3CACert P1anyPolicyMapping1to2CACert TrustAnchorRootCertificate
	ValidCertificatePathTest1EE ValidDNandRFC822nameConstraintsTest27EE ValidPolicyMappingTest12EE
	ValidPolicyMappingTest13EE ValidRFC822nameConstraintsTest21EE ValidinhibitPolicyMappingTest4EE
	ValidrequireExplicitPolicyTest1EE inhibitAnyPolicy1CACert inhibitAnyPolicy1subCA1Cert
	inhibitAnyPolicyTest3EE inhibitPolicyMapping1P12CACert inhibitPolicyMapping1P12subCACert
	inhibitPolicyMapping1P12subsubCACert nameConstraintsDN1CACert nameConstraintsDN1subCA3Cert
	nameConstraintsRFC822CA1Cert pathLenConstraint0CACert pathLenConstraint0subCACert
	requireExplicitPolicy10CACert requireExplicitPolicy10subCACert requireExplicitPolicy10subsubCACert
	requireExplicitPolicy10subsubsubCACert
)

for file in "${files[@]}"; do
	curl -fsSL "https://raw.githubusercontent.com/google/boringssl/main/pki/testdata/nist-pkits/certs/${file}.crt" \
		-o "${CERT_DIR}/${file}.crt" || {
		echo "Error: Failed to download ${file}.crt" >&2
		exit 1
	}
done

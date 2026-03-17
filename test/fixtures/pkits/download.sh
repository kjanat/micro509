#!/usr/bin/env bash

set -euo pipefail

# Copyright 2026 The micro509 Authors
#
# This script vendors the full PKITS fixture corpus from the BoringSSL mirror of
# the NIST PKITS inputs. It syncs certificates, CRLs, and the upstream testcase
# metadata used to generate the local manifest.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../../.." && pwd)"
PKITS_DIR="${REPO_ROOT}/test/fixtures/pkits"
CERT_DIR="${PKITS_DIR}/certs"
CRL_DIR="${PKITS_DIR}/crls"
UPSTREAM_DIR="${PKITS_DIR}/upstream"
UPSTREAM_API_ROOT="repos/google/boringssl/contents/pki/testdata/nist-pkits"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		printf 'Error: missing required command: %s\n' "$1" >&2
		exit 1
	}
}

sync_directory() {
	local upstream_path="$1"
	local destination_dir="$2"
	local extension="$3"

	mkdir -p "${destination_dir}"
	rm -f -- "${destination_dir}"/*."${extension}"

	gh api "${UPSTREAM_API_ROOT}/${upstream_path}" --jq '.[] | [.name, .download_url] | @tsv' \
		| while IFS=$'\t' read -r file_name download_url; do
			if [[ -z "${file_name}" || -z "${download_url}" ]]; then
				printf 'Error: malformed directory entry for %s\n' "${upstream_path}" >&2
				exit 1
			fi
			curl -fsSL "${download_url}" -o "${destination_dir}/${file_name}"
		done
}

sync_file() {
	local file_name="$1"
	local destination_dir="$2"
	mkdir -p "${destination_dir}"
	curl -fsSL "https://raw.githubusercontent.com/google/boringssl/main/pki/testdata/nist-pkits/${file_name}" \
		-o "${destination_dir}/${file_name}"
}

require_command bun
require_command curl
require_command gh

sync_directory certs "${CERT_DIR}" crt
sync_directory crls "${CRL_DIR}" crl
sync_file README.md "${UPSTREAM_DIR}"
sync_file generate_tests.py "${UPSTREAM_DIR}"
sync_file pkits_testcases-inl.h "${UPSTREAM_DIR}"

bun "${PKITS_DIR}/generate-manifest.ts"

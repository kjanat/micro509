#!/usr/bin/env bash
set -euo pipefail

EVENT_NAME="${EVENT_NAME:-}"
REF_NAME="${REF_NAME:-}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/stdout}"

# Read names + versions from both manifests
JSR_NAME=$(jq -r '.name // empty' jsr.json)
PKG_NAME=$(jq -r '.name // empty' package.json)
JSR_VERSION=$(jq -r '.version // empty' jsr.json)
PKG_VERSION=$(jq -r '.version // empty' package.json)

if [[ -z "${JSR_VERSION}" ]]; then
	echo "::error::Missing or empty version in jsr.json"
	exit 1
fi
if [[ -z "${PKG_VERSION}" ]]; then
	echo "::error::Missing or empty version in package.json"
	exit 1
fi
if [[ "${JSR_VERSION}" != "${PKG_VERSION}" ]]; then
	echo "::error::Version mismatch: jsr.json=${JSR_VERSION}, package.json=${PKG_VERSION}"
	exit 1
fi

IS_PUSH=false
IS_TAG=false

case "${EVENT_NAME}" in
	pull_request)
		echo "PR mode: version from manifests: ${JSR_VERSION}"
		VERSION="v${JSR_VERSION}"
		;;
	push)
		IS_PUSH=true
		if [[ "${REF_NAME}" != v* ]]; then
			echo "::error::Push event requires REF_NAME starting with 'v', got: ${REF_NAME}"
			exit 1
		fi
		IS_TAG=true
		VERSION="${REF_NAME}"
		SEMVER="${VERSION#v}"
		echo "Tag version: ${SEMVER}"
		echo "Manifest version: ${JSR_VERSION}"
		if [[ "${SEMVER}" != "${JSR_VERSION}" ]]; then
			echo "::error::Version mismatch: tag=${SEMVER}, manifests=${JSR_VERSION}"
			exit 1
		fi
		;;
	*)
		echo "::error::Unsupported event: ${EVENT_NAME:-<empty>}"
		exit 1
		;;
esac

IS_PRERELEASE=false
IS_STABLE=false
if [[ "${VERSION}" == *-* ]]; then
	IS_PRERELEASE=true
elif [[ "${IS_TAG}" == "true" ]]; then
	IS_STABLE=true
fi

if [[ "${IS_TAG}" == "true" ]]; then MODE="publish"; else MODE="dry-run"; fi

# Registry URLs, built here (bare semver, no leading "v") so the workflow can
# reference them directly instead of reconstructing strings in YAML expressions.
VERSION_NUMBER="${VERSION#v}"
JSR_URL="https://jsr.io/${JSR_NAME}@${VERSION_NUMBER}"
NPM_URL="https://npm.im/package/${PKG_NAME}/v/${VERSION_NUMBER}"

{
	echo "version=${VERSION}"
	echo "is_push=${IS_PUSH}"
	echo "is_tag=${IS_TAG}"
	echo "prerelease=${IS_PRERELEASE}"
	echo "is_stable=${IS_STABLE}"
	echo "mode=${MODE}"
	echo "jsr_url=${JSR_URL}"
	echo "npm_url=${NPM_URL}"
} >>"${GITHUB_OUTPUT}"

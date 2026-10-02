# OpenSSL builds

Statically linked OpenSSL, built from the upstream release tarballs by [`openssl.yml`]. A daily run builds the newest OpenSSL release, the newest beta and the newest alpha.

## Which one to use

| You want OpenSSL                                            | Use                                              |
| ----------------------------------------------------------- | ------------------------------------------------ |
| in a GitHub Actions job, on any runner                      | the [`setup-openssl`] action                     |
| in a container, or copied into your own image (Linux x64)   | the image [`ghcr.io/kjanat/openssl`]             |
| as a binary for Linux, macOS or Windows, outside of Actions | the tarballs [`ghcr.io/kjanat/openssl-prebuilt`] |

## Tags

Both packages have the same tags.

| Tag                      | Points at                                    |
| ------------------------ | -------------------------------------------- |
| `latest`                 | the newest OpenSSL release                   |
| `beta`                   | the newest OpenSSL beta                      |
| `alpha`                  | the newest OpenSSL alpha                     |
| `4.0.2`                  | the newest build of OpenSSL 4.0.2            |
| `4.0.2-20260928`         | the newest build of 4.0.2 made on 2026-09-28 |
| `4.0.2-run36446405032.1` | the build made by that workflow run, forever |

Pin a run tag or a digest to keep exactly the same build.

## GitHub Actions

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: kjanat/micro509/.github/actions/setup-openssl@<commit-sha>
        with: { version: 4.0.2 }
      - run: openssl version
```

The action runs on Linux, macOS and Windows runners, x64 and arm64. It downloads the runner's tarball, verifies its build provenance attestation, puts `openssl` on `PATH` and sets `OPENSSL_CONF`. The `openssl-path` output holds the path to the binary. Builds from a fork need `repository` and `source-ref`, which default to `kjanat/micro509` and `refs/heads/master`.

## Container image

The image is `FROM scratch` with OpenSSL under `/usr/local`, for `linux/amd64`. Its entrypoint is `openssl` and its working directory is `/w`.

```sh
docker run --rm ghcr.io/kjanat/openssl:4.0.2 version -a
docker run --rm --user "$(id -u):$(id -g)" -v "${PWD}:/w" \
  ghcr.io/kjanat/openssl:4.0.2 x509 -in cert.pem -noout -text
```

To add OpenSSL to your own image:

```dockerfile
COPY --from=ghcr.io/kjanat/openssl:4.0.2 /usr/local/ /usr/local/
```

## Tarballs

`ghcr.io/kjanat/openssl-prebuilt:<tag>` holds one tarball per platform:\
`openssl-<version>-<platform>.tar.gz` for `linux-x64`, `linux-arm64`, `darwin-x64`, `darwin-arm64`, `windows-x64` and `windows-arm64`.\
Each tarball contains `bin/`, `lib/`, `include/` and `ssl/`.

Download all six with [ORAS]:

```sh
oras pull ghcr.io/kjanat/openssl-prebuilt:4.0.2
```

Download one:

```sh
tag='4.0.2'
ref="ghcr.io/kjanat/openssl-prebuilt:${tag}"
file="openssl-${tag}-darwin-arm64.tar.gz"
digest="$(oras manifest fetch "${ref}" | jq -r --arg f "${file}" '.layers[] | select(.annotations["org.opencontainers.image.title"] == $f) | .digest')"
oras blob fetch --output "${file}" "ghcr.io/kjanat/openssl-prebuilt@${digest}"
# ...
```

Extract it and point `OPENSSL_CONF` at its `openssl.cnf`:

```sh
# ..
dir="${PWD}/openssl"
mkdir -p "${dir}" && \
  tar -xzf "${file}" -C "${dir}"

PATH="${dir}/bin:${PATH}"
OPENSSL_CONF="${dir}/ssl/openssl.cnf"

export PATH OPENSSL_CONF
```

## Verify a build

Every image and tarball has a build provenance attestation. Each image also has two SPDX SBOMs.

```sh
image="ghcr.io/kjanat/openssl:${tag}"
ref='refs/heads/master'
repo='kjanat/micro509'
workflow="${repo}/.github/workflows/openssl.yml"

oci="oci://${image}"
file="openssl-${tag}-darwin-arm64.tar.gz"

gh attestation verify "${oci}"  --repo "${repo}" --signer-workflow "${workflow}" --source-ref "${ref}"
gh attestation verify "${file}" --repo "${repo}" --signer-workflow "${workflow}" --source-ref "${ref}"
```

<details><summary>or fully written out:</summary>

```sh
# or fully written out:
gh attestation verify oci://ghcr.io/kjanat/openssl:4.0.2 \
  --repo kjanat/micro509 \
  --signer-workflow kjanat/micro509/.github/workflows/openssl.yml \
  --source-ref refs/heads/master
gh attestation verify openssl-4.0.2-darwin-arm64.tar.gz \
  --repo kjanat/micro509 \
  --signer-workflow kjanat/micro509/.github/workflows/openssl.yml \
  --source-ref refs/heads/master
```

</details>

Add `--predicate-type https://spdx.dev/Document/v2.3` to verify an image's SBOMs.

[ORAS]: https://oras.land
[`ghcr.io/kjanat/openssl-prebuilt`]: https://ghcr.io/kjanat/openssl-prebuilt
[`ghcr.io/kjanat/openssl`]: https://ghcr.io/kjanat/openssl
[`openssl.yml`]: ../workflows/openssl.yml
[`setup-openssl`]: ../actions/setup-openssl/action.yml

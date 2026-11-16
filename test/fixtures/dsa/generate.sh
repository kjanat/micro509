#!/usr/bin/env bash
set -euo pipefail

out="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 \
	-pkeyopt dsa_paramgen_q_bits:256 -out params.txt
openssl genpkey -paramfile params.txt -out ca.k8
openssl genpkey -paramfile params.txt -out leaf.k8

openssl req -x509 -new -key ca.k8 -sha256 -subj '/CN=DSA Fixture CA' -days 36500 \
	-set_serial 1 \
	-addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature' \
	-out ca.txt
openssl req -new -key leaf.k8 -sha256 -subj '/CN=dsa-leaf.example' -out leaf-csr.txt
printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' >leaf.ext
openssl x509 -req -in leaf-csr.txt -CA ca.txt -CAkey ca.k8 -sha256 -days 36500 \
	-set_serial 2 -extfile leaf.ext -out leaf.txt

printf 'V\t491231235959Z\t\t02\tunknown\t/CN=dsa-leaf.example\n' >index.txt
printf '01\n' >crlnumber
cat >ca.cnf <<'EOF'
[ca]
default_ca = fixture
[fixture]
database = index.txt
crlnumber = crlnumber
default_md = sha256
default_crl_days = 36500
EOF
openssl ca -config ca.cnf -gencrl -keyfile ca.k8 -cert ca.txt -out crl.txt

openssl ocsp -issuer ca.txt -cert leaf.txt -no_nonce -reqout ocsp-request.der
openssl ocsp -index index.txt -CA ca.txt -rsigner ca.txt -rkey ca.k8 -rmd sha256 \
	-reqin ocsp-request.der -ndays 36500 -respout ocsp-response.der
printf 'micro509 DSA CMS fixture' >content.bin
openssl cms -sign -binary -nodetach -md sha256 -in content.bin -signer leaf.txt \
	-inkey leaf.k8 -outform DER -out cms.der

openssl x509 -in ca.txt -outform DER -out "$out/ca.der"
openssl x509 -in leaf.txt -outform DER -out "$out/leaf.der"
openssl req -in leaf-csr.txt -outform DER -out "$out/leaf-csr.der"
openssl crl -in crl.txt -outform DER -out "$out/ca-crl.der"
cp ocsp-request.der "$out/ocsp-request.der"
cp ocsp-response.der "$out/ocsp-response.der"
cp cms.der "$out/cms.der"

#!/bin/sh
#
# Makes the test certificates: a CA, and a leaf for localhost it signs,
# ECDSA P-256, valid for a hundred years.  Test material only: the keys are
# public, here.  Run from this directory; it overwrites what is here.

set -eu

openssl ecparam -name prime256v1 -genkey -noout -out ca.pem
openssl req -x509 -new -key ca.pem -sha256 -days 36500 \
	-subj "/CN=npro test CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-out ca-cert.pem

openssl ecparam -name prime256v1 -genkey -noout -out leaf.pem
openssl req -new -key leaf.pem -subj "/CN=localhost" -out leaf.csr
printf '%s\n' "basicConstraints=critical,CA:FALSE" \
	"keyUsage=critical,digitalSignature" \
	"extendedKeyUsage=serverAuth" \
	"subjectAltName=DNS:localhost" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca.pem -CAcreateserial \
	-sha256 -days 36500 -extfile leaf.ext -out leaf-cert.pem

# DER, as the tests take them: no PEM parsing needed
openssl x509 -in ca-cert.pem -outform DER -out ca.der
openssl x509 -in leaf-cert.pem -outform DER -out leaf.der
openssl pkcs8 -topk8 -nocrypt -in leaf.pem -outform DER -out leaf-key.der

rm -f ca.pem ca-cert.pem leaf.pem leaf-cert.pem leaf.csr leaf.ext ca-cert.srl

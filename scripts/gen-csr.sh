#!/bin/bash
set -ex
cwd=`pwd`
trap "cd ${cwd}" EXIT

# namespace for storage on local files
environment=$1
# domain
domain=$2
# subject appended to the domain in the CN (common name) field
subj=$3

dir="${environment}-${domain}"
mkdir "${dir}"
cd "${dir}"
openssl genrsa -out key.pem 4096
if [ -z "${subj}" ]
then
  openssl req -new -sha256 -key key.pem -out certificate.csr
else
  openssl req -new -sha256 -key key.pem -subj "/CN=${domain}${subj}" -out certificate.csr
fi
openssl req -in certificate.csr -outform DER -out certificate.csr.der

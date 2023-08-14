#!/bin/bash
set -ex
cwd=`pwd`
trap "cd ${cwd}" EXIT

# namespace for storage on local files
environment=$1
# (sub)-domain
domain=$2
# subject appended to the domain in the CN (common name) field
subj=$3
# iteration
iteration=$4

csrfile="certificate.${iteration}.csr"

dir="${environment}-${domain}"
mkdir -p "${dir}"
cd "${dir}"

if [ ! -e "key.pem" ]
then
  openssl genrsa -out key.pem 4096
fi

if [ -z "${subj}" ]
then
  openssl req -new -sha256 -key key.pem -out "${csrfile}"
else
  openssl req -new -sha256 -key key.pem -subj "/CN=${domain}.${subj}" -out "${csrfile}"
fi
openssl req -in "${csrfile}" -outform DER -out "${csrfile}.der"

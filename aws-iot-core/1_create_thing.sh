#!/bin/bash

if ! command -v jq &> /dev/null
then
  echo "jq could not be found. Install it by $ sudo apt install jq."
  exit
fi

# read from config file
thingname=`jq -r '.ThingName' config.json`
policyname=`jq -r '.PolicyName' config.json`

# check if any thing with the same name exist
certificateArn=`aws iot list-thing-principals --thing-name $thingname 2> /dev/null | jq -r '.principals[0]'`

if [ ! -z "${certificateArn}" ]
then
  echo "thing with the same name found, please remove it before executing a new request."
  exit
fi

# transmit csr and request for client certificate
certificateArn=`aws iot create-certificate-from-csr --certificate-signing-request file://out//tpm.csr --set-as-active --certificate-pem-outfile out/tpm.crt | jq -r '.certificateArn'`

if [ -z "${certificateArn}" ]
then
  echo "aws iot create-certificate-from-csr failed."
  exit
fi

# create a thing with the name $thingname
aws iot create-thing --thing-name $thingname

# create policy with $policyname
aws iot create-policy --policy-name $policyname --policy-document file://policy.json

# attach policy to the client certificate
aws iot attach-policy --policy-name $policyname --target $certificateArn

# attach client certificate to the thing
aws iot attach-thing-principal --thing-name $thingname --principal $certificateArn

# download Amazon root CA
curl --url https://www.amazontrust.com/repository/AmazonRootCA1.pem -o out/AmazonRootCA1.pem.crt

# Read cert
#openssl x509 -in out/tpm.crt -text -noout

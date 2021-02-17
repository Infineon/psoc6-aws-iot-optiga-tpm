#!/bin/bash

# read from config file
thingname=`jq -r '.ThingName' config.jsn`
policyname=`jq -r '.PolicyName' config.jsn`

cp csr/tpm.pem.csr ./

# create a thing with the name $thingname
aws iot create-thing --thing-name $thingname

# create policy with $policyname
aws iot create-policy --policy-name $policyname --policy-document file://policy.jsn

# output of create-cert-from-csr is in json format
certificateArn=`aws iot create-certificate-from-csr --certificate-signing-request file://tpm.pem.csr --set-as-active --certificate-pem-outfile tpm.pem.crt | jq -r '.certificateArn'`

aws iot attach-thing-principal --thing-name $thingname --principal $certificateArn

aws iot attach-policy --policy-name $policyname --target $certificateArn


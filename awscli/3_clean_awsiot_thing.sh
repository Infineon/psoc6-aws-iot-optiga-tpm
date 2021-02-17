#!/bin/bash

# read from config file
thingname=`jq -r '.ThingName' config.jsn`
policyname=`jq -r '.PolicyName' config.jsn`

# remove files
rm tpm.pem.csr
rm tpm.pem.crt

# get thing's certificate arn and id
certificateArn=`aws iot list-thing-principals --thing-name $thingname | jq -r '.principals[0]'`
certificateID=`echo $certificateArn | awk -F'cert/' '{print $2}'`

# detech policy from certificate
aws iot detach-policy --policy-name $policyname --target $certificateArn

# detech certificate from thing
aws iot detach-thing-principal --thing-name $thingname --principal $certificateArn

# deactivate certificate
aws iot update-certificate --new-status INACTIVE --certificate-id  $certificateID

# delete certificate
aws iot delete-certificate --force-delete --certificate-id $certificateID

# delete policy
aws iot delete-policy --policy-name $policyname

# delete thing
aws iot delete-thing --thing-name $thingname





#!/bin/bash

if ! command -v jq &> /dev/null
then
  echo "jq could not be found. Install it by $ sudo apt install jq."
  exit
fi

# read from config file
thingname=`jq -r '.ThingName' config.json`
policyname=`jq -r '.PolicyName' config.json`

# get thing's certificate arn and id
certificateArn=`aws iot list-thing-principals --thing-name $thingname 2> /dev/null | jq -r '.principals[0]'`

if [ -z "${certificateArn}" ]
then
  echo "thing not found, unable to proceed."
  exit
fi

certificateID=`echo $certificateArn | awk -F'cert/' '{print $2}'`

# detach policy from certificate
aws iot detach-policy --policy-name $policyname --target $certificateArn

# detach certificate from thing
aws iot detach-thing-principal --thing-name $thingname --principal $certificateArn

# deactivate certificate
aws iot update-certificate --new-status INACTIVE --certificate-id  $certificateID

# delete certificate
aws iot delete-certificate --force-delete --certificate-id $certificateID

# delete policy
aws iot delete-policy --policy-name $policyname

# delete thing
aws iot delete-thing --thing-name $thingname

# remove files
rm -f out/*.crt 2> /dev/null

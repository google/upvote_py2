#!/bin/bash
if [[ -z "${PROJ_ID}" ]]; then
  echo "Error: \$PROJ_ID environment variable is undefined"
  echo "  To locate your project ID, see https://support.google.com/cloud/answer/6158840?hl=en"
  echo "  To set it, run \"export PROJ_ID=my-proj-id\""
  exit 1
elif [[ -e WORKSPACE ]]; then
  echo "Error: Must be run from upvote root directory"
  exit 1
elif [[ -z $(which gcloud) ]]; then
  echo "Error: gcloud not found on PATH"
  echo "  To install the Cloud SDK, see https://cloud.google.com/sdk/downloads"
  exit 1
elif [[ -z $(which bazel) ]]; then
  echo "Error: bazel build tool not found on PATH"
  echo "  To install Bazel, see https://docs.bazel.build/versions/master/install.html"
  exit 1
fi
printf 'Initializing Upvote for GCP project: "%s"\n' "${PROJ_ID}"

set -xe

gcloud config set project "${PROJ_ID}"

echo Enabling App Engine...
if [[ "$(gcloud app describe --format='value(id)')" -ne "${PROJ_ID}" ]]; then
  gcloud app create
fi

echo Enabling APIs used by Upvote...
gcloud services enable cloudkms.googleapis.com
gcloud services enable bigquery-json.googleapis.com

echo Creating encryption keys used to store Upvote API secrets...
gcloud kms keyrings create ring --location=global
gcloud kms keys create virustotal --purpose=encryption --keyring=ring --location=global

echo Granting necessary permissions to App Engine...
SERVICE_ACCOUNT=$(gcloud iam service-accounts list --filter="App Engine app default service account" --format="value(email)")
gcloud projects add-iam-policy-binding "${PROJ_ID}" --member serviceAccount:"${SERVICE_ACCOUNT}" --role roles/cloudkms.cryptoKeyEncrypterDecrypter

echo Deploying to App Engine...
./manage_crons.py disable_all
bazel run upvote/gae:monolith_binary.deploy -- "${PROJ_ID}" app.yaml santa_api.yaml bit9_api.yaml

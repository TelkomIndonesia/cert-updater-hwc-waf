#!/bin/bash

DEFAULT_BASE_FOLDER="/var/run/secrets/certs"
BASE_FOLDER=${BASE_FOLDER:-$DEFAULT_BASE_FOLDER}
inotifywait -m -r $BASE_FOLDER -e moved_to |
    while read path action file; do
            DIR=$(basename "$path")
            CERT_FOLDER="$BASE_FOLDER/$DIR"
            CERT_PATH="$CERT_FOLDER/tls.crt"
            KEY_PATH="$CERT_FOLDER/tls.key"
            python3 "./api.py" --iam-domain $IAM_DOMAIN --iam-user $IAM_USER --iam-password $IAM_PASSWORD --region-id $PROJECT_NAME --cert-name $DIR --cert-path $CERT_PATH --key-path $KEY_PATH
    done
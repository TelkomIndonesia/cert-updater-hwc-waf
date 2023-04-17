#!/bin/bash

DEFAULT_BASE_FOLDER="/etc/secrets"
BASE_FOLDER=${BASE_FOLDER:-$DEFAULT_BASE_FOLDER}
inotifywait -m -r $BASE_FOLDER -e moved_to |
    while read path action file; do
            CERT_NAME=$(basename "$path")
            CERT_FOLDER="$BASE_FOLDER/$CERT_NAME"
            CERT_PATH="$CERT_FOLDER/tls.crt"
            KEY_PATH="$CERT_FOLDER/tls.key"
            python3 "./api.py" --iam-domain $IAM_DOMAIN --iam-user $IAM_USER --iam-password $IAM_PASSWORD --project-name $PROJECT_NAME --project-id $PROJECT_ID --enterprise-project-id $ENTERPRISE_PROJECT_ID --cert-name $CERT_NAME --cert-path $CERT_PATH --key-path $KEY_PATH
    done
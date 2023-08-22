#!/bin/bash

BASE_FOLDER=${BASE_FOLDER:-"/var/run/secrets/certs"}

inotifywait -m -r "$BASE_FOLDER" -e moved_to |
        while read path action file; do
                CERT_NAME=$(basename "$path")
                CERT_FOLDER="$BASE_FOLDER/$CERT_NAME"
                CERT_PATH="$CERT_FOLDER/tls.crt"
                KEY_PATH="$CERT_FOLDER/tls.key"

                python3 "./cert-updater.py" \
                        --iam-domain "$IAM_DOMAIN" \
                        --iam-user "$IAM_USER" \
                        --iam-password "$IAM_PASSWORD" \
                        --region-id "$PROJECT_NAME" \
                        --cert-name "$CERT_NAME" \
                        --cert-path "$CERT_PATH" \
                        --key-path "$KEY_PATH"
        done

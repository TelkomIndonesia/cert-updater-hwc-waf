#!/usr/bin/env python3

import json
import requests
import argparse
import time

timestamp = int(time.time())

parser = argparse.ArgumentParser(description='Modify certificate in Huawei WAF')
parser.add_argument('--iam-domain', type=str, required=True,
                    help='IAM domain name')
parser.add_argument('--iam-user', type=str, required=True,
                    help='IAM user name')
parser.add_argument('--iam-password', type=str, required=True,
                    help='IAM user password')
parser.add_argument('--project-name', type=str, required=True,
                    help='Name of the project')
parser.add_argument('--project-id', type=str, required=True,
                    help='Project ID')
parser.add_argument('--enterprise-project-id', type=str, required=True,
                    help='Enterprise Project ID')
parser.add_argument('--cert-name', type=str, required=True,
                    help='Name of the certificate to modify')
parser.add_argument('--cert-path', type=str, required=True,
                    help='Path to the certificate file')
parser.add_argument('--key-path', type=str, required=True,
                    help='Path to the private key file')
parser.add_argument('--host-id', type=str, required=True,
                    help='Host Id')
args = parser.parse_args()

# Set variables for the request
url = "https://iam.myhuaweicloud.com/v3/auth/tokens?nocatalog=true"
IAMDomain = args.iam_domain
IAMUser = args.iam_user
IAMPassword = args.iam_password
projectName = args.project_name
projectId = args.project_id
enterpriseProjectId = args.enterprise_project_id
cert_name = args.cert_name+"_"+str(timestamp)
cert_path = args.cert_path
key_path = args.key_path
host_id = args.host_id

payload = {
    "auth": {
        "identity": {
            "methods": ["password"],
            "password": {
                "user": {
                    "domain": {
                        "name": IAMDomain
                    },
                    "name": IAMUser,
                    "password": IAMPassword
                }
            }
        },
        "scope": {
            "project": {
                "name": projectName
            }
        }
    }
}
headers = {"Content-Type": "application/json"}
response = requests.post(url, headers=headers, json=payload)
token = response.headers.get("X-Subject-Token")

url_upload_cert = "https://waf."+projectName+".myhuaweicloud.com/v1/"+projectId+"/waf/certificate?enterprise_project_id="+enterpriseProjectId
with open(cert_path, 'rb') as file:
    cert = file.read()
    if cert.endswith(b'\n'):
        cert = cert[:-1]
    cert = cert.decode()
with open(key_path, 'rb') as file:
    key = file.read()
    if key.endswith(b'\n'):
        key = key[:-1]
    key = key.decode()

payload_upload_cert = {
    "name": cert_name,
    "content" : cert,
    "key" : key
}

headers_auth = {
    "X-Auth-Token": token,
    "Content-Type": "application/json"
    }

print("Uploaded Certificate "+cert_name)
response_upload= requests.post(url_upload_cert, headers=headers_auth, json=payload_upload_cert)
certificate_id = response_upload.json()["id"]
print(certificate_id)

url_apply_cert = "https://waf."+projectName+".myhuaweicloud.com/v1/"+projectId+"/waf/certificate/"+certificate_id+"/apply-to-hosts?enterprise_project_id="+enterpriseProjectId
payload_apply_host = {
  "cloud_host_ids" : [ host_id ]
}
response_apply= requests.post(url_apply_cert, headers=headers_auth, json=payload_apply_host)
print(response_apply.json())
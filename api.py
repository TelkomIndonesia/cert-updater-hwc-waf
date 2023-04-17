#!/usr/bin/env python3

import json
import requests
import argparse

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
args = parser.parse_args()

# Set variables for the request
url = "https://iam.myhuaweicloud.com/v3/auth/tokens?nocatalog=true"
IAMDomain = args.iam_domain
IAMUser = args.iam_user
IAMPassword = args.iam_password
projectName = args.project_name
projectId = args.project_id
enterpriseProjectId = args.enterprise_project_id
cert_name = args.cert_name
cert_path = args.cert_path
key_path = args.key_path

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


url_get_list_cert = "https://waf."+projectName+".myhuaweicloud.com/v1/"+projectId+"/waf/certificate?enterprise_project_id="+enterpriseProjectId+"&name="+cert_name
headers_auth = {
    "X-Auth-Token": token,
    "Content-Type": "application/json"
    }
response2 = requests.get(url_get_list_cert, headers=headers_auth)
response_cert = response2.json()
certificate_id = response_cert['items'][0]['certificateid']

url_modify_cert = "https://waf."+projectName+".myhuaweicloud.com/v1/"+projectId+"/waf/certificate/"+certificate_id+"?enterprise_project_id="+enterpriseProjectId
with open(cert_path, 'r') as file:
    cert = file.read()
with open(key_path, 'r') as file:
    key = file.read()

print(url_modify_cert)
payload_modify_cert = {
    "name": cert_name,
    "content" : cert,
    "key" : key
}


print("Modify Certificate "+certificate_id)
response_modify = requests.put(url_modify_cert, headers=headers_auth, json=payload_modify_cert)
print(response_modify.json())

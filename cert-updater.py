#!/usr/bin/env python3

import requests
import argparse
import time
import yaml


def get_token(iam_domain, iam_user, iam_password, project_name, url):
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {"name": iam_domain},
                        "name": iam_user,
                        "password": iam_password,
                    }
                },
            },
            "scope": {"project": {"name": project_name}},
        }
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()

        token = response.headers.get("X-Subject-Token")
        return token

    except requests.HTTPError as e:
        print(f"Failed to obtain token. HTTP Error: {e}")
        return None


def upload_certificate(
    region_id,
    project_id,
    enterprise_project_id,
    cert_path,
    key_path,
    cert_name,
    token,
):
    timestamp = int(time.time())
    cert_name = cert_name + "_" + str(timestamp)
    # Construct the URL.
    url_upload_cert = f"https://waf.{region_id}.myhuaweicloud.com/v1/{project_id}/waf/certificate?enterprise_project_id={enterprise_project_id}"

    # Read and preprocess the certificate.
    with open(cert_path, "rb") as file:
        cert = file.read()
        if cert.endswith(b"\n"):
            cert = cert[:-1]
        cert = cert.decode()

    # Read and preprocess the key.
    with open(key_path, "rb") as file:
        key = file.read()
        if key.endswith(b"\n"):
            key = key[:-1]
        key = key.decode()

    # Prepare the payload and headers.

    payload_upload_cert = {"name": cert_name, "content": cert, "key": key}
    headers_auth = {"X-Auth-Token": token, "Content-Type": "application/json"}
    try:
        response = requests.post(
            url_upload_cert, headers=headers_auth, json=payload_upload_cert
        )
        response.raise_for_status()  # Raise exception for unsuccessful status codes.
        certificate_id = response.json()["id"]
        return certificate_id

    except requests.HTTPError as e:
        print(f"Failed to upload certificate. HTTP Error: {e}")
        return None


def apply_certificate(
    project_name,
    project_id,
    enterprise_project_id,
    certificate_id,
    host_id,
    token,
):
    # Construct the URL.
    url_apply_cert = f"https://waf.{project_name}.myhuaweicloud.com/v1/{project_id}/waf/certificate/{certificate_id}/apply-to-hosts?enterprise_project_id={enterprise_project_id}"

    # Prepare the payload and headers.
    payload_apply_host = {"cloud_host_ids": [host_id]}
    headers_auth = {"X-Auth-Token": token, "Content-Type": "application/json"}

    try:
        response_apply = requests.post(
            url_apply_cert, headers=headers_auth, json=payload_apply_host
        )
        response_apply.raise_for_status()  # Raise exception for unsuccessful status codes.
        print("Certificate applied successfully!")
        return response_apply.json()

    except requests.HTTPError as e:
        print(f"Failed to apply certificate. HTTP Error: {e}")
        return None


def get_prev_cert_id(region_id, project_id, host_id, enterprise_project_id, token):
    # Construct the URL.
    url = f"https://waf.{region_id}.myhuaweicloud.com/v1/{project_id}/waf/instance/{host_id}?enterprise_project_id={enterprise_project_id}"

    # Prepare the headers.
    headers_auth = {"X-Auth-Token": token, "Content-Type": "application/json"}

    try:
        response = requests.get(url, headers=headers_auth)
        response.raise_for_status()  # Raise exception for unsuccessful status codes.
        data = response.json()
        certificateid = data.get("certificateid", None)

        if not certificateid:
            print("certificateid not found in the host details.")
            return None

        return certificateid

    except requests.HTTPError as e:
        print(f"Failed to fetch host details. HTTP Error: {e}")
        return None


def get_certificate_details(
    region_id,
    project_id,
    certificate_id,
    enterprise_project_id,
    token,
):
    url = f"https://waf.{region_id}.myhuaweicloud.com/v1/{project_id}/waf/certificate/{certificate_id}?enterprise_project_id={enterprise_project_id}"

    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    except requests.HTTPError as e:
        print(f"Error fetching certificate details. HTTP Error: {e}")
        return None


def delete_certificate(
    region_id,
    project_id,
    certificate_id,
    enterprise_project_id,
    token,
):
    cert_details = get_certificate_details(
        region_id, project_id, certificate_id, enterprise_project_id, token
    )
    if not cert_details or cert_details.get("bind_host", []):
        print(
            "Certificate is either not found or currently bound to hosts. Aborting deletion."
        )
        return False
    # Construct the URL.
    url = f"https://waf.{region_id}.myhuaweicloud.com/v1/{project_id}/waf/certificate/{certificate_id}?enterprise_project_id={enterprise_project_id}"

    # Prepare the headers.
    headers_auth = {"X-Auth-Token": token, "Content-Type": "application/json"}

    try:
        response = requests.delete(url, headers=headers_auth)
        response.raise_for_status()  # Raise exception for unsuccessful status codes.

        # If the response has a different status code.
        print(f"Success to delete certificate. Status code: {response.status_code}")
        return False

    except requests.HTTPError as e:
        print(f"Failed to delete certificate. HTTP Error: {e}")
        return False


def read_yaml(filename):
    """Loads content of a YAML file into a Python dictionary."""
    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
            return data
        except yaml.YAMLError as exc:
            print(exc)


def get_host_details_by_cert_name(filename, cert_name):
    """Given a cert_name, retrieves the host_ids and their associated details."""
    data = read_yaml(filename)
    if not data:
        return {}

    return data.get(cert_name, {})


def main(
    iam_domain,
    iam_user,
    iam_password,
    region_id,
    url,
    cert_path,
    key_path,
    cert_name,
):
    # Step 1: Login and get token
    token = get_token(iam_domain, iam_user, iam_password, region_id, url)
    if not token:
        print("Failed to obtain token. Exiting!")
        return

    cert_id = get_host_details_by_cert_name("config.yaml", cert_name)
    print(cert_id)
    for item in cert_id:
        enterprise_id = item["enterprise_id"]
        project_id = item["project_id"]
        # Step 2: Upload Certificate
        certificate_id = upload_certificate(
            region_id,
            project_id,
            enterprise_id,
            cert_path,
            key_path,
            cert_name,
            token,
        )
        if not certificate_id:
            print("Failed to upload certificate. Exiting!")
            return

        hosts = item["hosts"]
        for host in hosts:
            prev_cert_id = get_prev_cert_id(
                region_id, project_id, host, enterprise_id, token
            )
            if not prev_cert_id:
                print("Failed to obtain Previous Certificate ID. Exiting!")
                return
            response_apply = apply_certificate(
                region_id, project_id, enterprise_id, certificate_id, host, token
            )
            if not response_apply:
                print("Failed to apply certificate. Exiting!")
                return
            print(prev_cert_id)
            delete_certificate(
                region_id, project_id, prev_cert_id, enterprise_id, token
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modify certificate in Huawei WAF")
    parser.add_argument("--iam-domain", type=str, required=True, help="IAM domain name")
    parser.add_argument("--iam-user", type=str, required=True, help="IAM user name")
    parser.add_argument(
        "--iam-password", type=str, required=True, help="IAM user password"
    )
    parser.add_argument(
        "--region-id", type=str, required=True, help="Name of the region"
    )
    parser.add_argument(
        "--cert-name", type=str, required=True, help="Name of the certificate to modify"
    )
    parser.add_argument(
        "--cert-path", type=str, required=True, help="Path to the certificate file"
    )
    parser.add_argument(
        "--key-path", type=str, required=True, help="Path to the private key file"
    )
    args = parser.parse_args()

    # Set variables for the request
    url = "https://iam.myhuaweicloud.com/v3/auth/tokens?nocatalog=true"
    iam_domain = args.iam_domain
    iam_user = args.iam_user
    iam_password = args.iam_password
    region_id = args.region_id
    cert_name = args.cert_name
    cert_path = args.cert_path
    key_path = args.key_path

    main(
        iam_domain,
        iam_user,
        iam_password,
        region_id,
        url,
        cert_path,
        key_path,
        cert_name,
    )

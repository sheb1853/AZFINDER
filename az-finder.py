#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
import requests
import sys
import os
from tabulate import tabulate

BANNER = """
 AAAAA   ZZZZZZZ  FFFFFF  IIIII  N   N  DDDDD  EEEEE  RRRRR 
A     A      Z    F         I    NN  N  D    D E      R    R
AAAAAAA     Z     FFFFF     I    N N N  D    D EEEEE  RRRRR 
A     A    Z      F         I    N  NN  D    D E      R  R  
A     A  ZZZZZZZ  F       IIIII  N   N  DDDDD  EEEEE  R   RR
		
			by timothians
"""

USAGE = """
az-finder is a tool for enumerating Azure AD (Entra ID) domains and tenant information.

Usage:
  az-finder [flags]

INPUT:
   -d                  domain to find information about
   -l file             file containing list of domains

OUTPUT:
   -o file             file to write output (supports .txt or .html files)

EXAMPLES:
   az-finder -d example.com -o output.html
   az-finder -l /tmp/domains.txt -o output.txt
"""

def print_banner():
    print(BANNER)

def custom_usage():
    print(BANNER)
    print(USAGE)

def fetch_tenant_domains(domain):
    body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
    <soap:Header>
        <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
        <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
    </soap:Header>
    <soap:Body>
        <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
        </GetFederationInformationRequestMessage>
    </soap:Body>
</soap:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        "User-Agent": "AutodiscoverClient",
    }

    response = requests.post(
        "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", 
        data=body, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Request failed with status {response.status_code}")

    try:
        root = ET.fromstring(response.content)

        # Correct XML Path to Domains
        namespace = {'soap': 'http://schemas.xmlsoap.org/soap/envelope/', 'autodiscover': 'http://schemas.microsoft.com/exchange/2010/Autodiscover'}
        domains = root.findall(".//autodiscover:Domain", namespace)

        return [domain.text for domain in domains]
    except Exception as e:
        print(f"Error parsing related domains: {e}")
        return []

def fetch_openid_config(domain):
    openid_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    response = requests.get(openid_url)

    if response.status_code == 400:
        print(f"[!] OpenID configuration fetch failed for domain {domain} (status: 400). Skipping tenant info...")
        return None, None
    elif response.status_code != 200:
        raise Exception(f"Failed to fetch OpenID configuration, status: {response.status_code}")

    config = response.json()
    tenant_id = config["issuer"].split("/")[-2]  # Corrected to fetch the tenant ID correctly
    return config, tenant_id

def fetch_user_realm_info(domain):
    api_url = f"https://login.microsoftonline.com/getuserrealm.srf?login={domain}&json=1"
    response = requests.get(api_url)

    if response.status_code != 200:
        raise Exception(f"Request to getuserrealm.srf failed with status {response.status_code}")

    realm_info = response.json()
    if not realm_info.get("AuthURL"):
        realm_info["AuthURL"] = "N/A"
    return realm_info

def write_to_file(file_path, content):
    with open(file_path, "w") as f:
        f.write(content)

def generate_html_table(headers, rows):
    html_content = "<table border='1'>"
    html_content += "<tr>" + "".join([f"<th>{header}</th>" for header in headers]) + "</tr>"
    for row in rows:
        html_content += "<tr>" + "".join([f"<td>{cell}</td>" for cell in row]) + "</tr>"
    html_content += "</table>"
    return html_content

def handle_domain_check(domain, output_file, append=False):
    try:
        related_domains = fetch_tenant_domains(domain)
    except Exception as e:
        print(f"[!] Error fetching tenant domains for {domain}: {e}")
        related_domains = []

    headers = ["Related Domains"]
    rows = [[rel_domain] for rel_domain in related_domains]

    if output_file:
        file_ext = os.path.splitext(output_file)[-1].lower()
        mode = 'a' if append else 'w'
        if file_ext == ".html":
            html_content = f"<h1>Domains related to {domain}</h1>" + generate_html_table(headers, rows)
            with open(output_file, mode) as f:
                f.write(html_content)
        elif file_ext == ".txt":
            text_content = tabulate(rows, headers=headers)
            with open(output_file, mode) as f:
                f.write(text_content + "\n")
        else:
            print(f"Unsupported file format: {file_ext}")
    else:
        print(f"[*] Domains related to {domain}:")
        print(tabulate(rows, headers=headers, tablefmt="grid"))

def handle_tenant_check(domain, output_file, append=False):
    openid_config, tenant_id = fetch_openid_config(domain)

    if not openid_config or not tenant_id:
        print(f"[!] Skipping tenant info for domain {domain} as OpenID configuration failed.")
        return

    try:
        realm_info = fetch_user_realm_info(domain)
    except Exception as e:
        print(f"[!] Error fetching user realm info for {domain}: {e}")
        realm_info = {
            "FederationBrandName": "N/A",
            "NameSpaceType": "N/A",
            "AuthURL": "N/A"
        }

    tenant_info = {
        "root_domain": domain,
        "federation_brand": realm_info.get("FederationBrandName", "N/A"),
        "tenant_id": tenant_id,
        "tenant_region": openid_config.get("tenant_region_scope", "N/A"),
        "namespace_type": realm_info.get("NameSpaceType", "N/A"),
        "auth_url": realm_info.get("AuthURL", "N/A")
    }

    headers = ["Tenant Info", "Details"]
    rows = [
        ["Tenant Brand Name", tenant_info['federation_brand']],
        ["Tenant ID", tenant_info['tenant_id']],
        ["Tenant Region", tenant_info['tenant_region']],
        ["Namespace Type", tenant_info['namespace_type']],
        ["Auth URL (SSO)", tenant_info['auth_url']]
    ]

    if output_file:
        file_ext = os.path.splitext(output_file)[-1].lower()
        mode = 'a' if append else 'w'
        if file_ext == ".html":
            html_content = f"<h1>Tenant Information for {domain}</h1>" + generate_html_table(headers, rows)
            with open(output_file, mode) as f:
                f.write(html_content)
        elif file_ext == ".txt":
            text_content = tabulate(rows, headers=headers)
            with open(output_file, mode) as f:
                f.write(text_content + "\n")
        else:
            print(f"Unsupported file format: {file_ext}")
    else:
        print(f"[*] Tenant information for domain {domain}:")
        print(tabulate(rows, headers=headers, tablefmt="grid"))

def read_domains_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except Exception as e:
        print(f"Error reading domain file {file_path}: {e}")
        return []

def main():
    # Always print the banner
    print_banner()

    # Create the ArgumentParser with allow_abbrev set to False to prevent abbreviation
    parser = argparse.ArgumentParser(
        description="az-finder is a tool for enumerating Azure AD (Entra ID) domains and tenant information.", 
        allow_abbrev=False  # Prevent abbreviations like -domain being misinterpreted as -d
    )

    parser.add_argument("-d", help="Domain to find information about")
    parser.add_argument("-l", help="File containing list of domains")
    parser.add_argument("-o", help="File to write output (supports .txt or .html files)")

    # Parse arguments
    args = parser.parse_args()

    # If no domain or file list is provided, print the custom usage and exit
    if not args.d and not args.l:
        custom_usage()
        sys.exit(1)

    # Handle domain and tenant information
    if args.d:
        handle_domain_check(args.d, args.o, append=False)
        handle_tenant_check(args.d, args.o, append=True)

    if args.l:
        domains = read_domains_from_file(args.l)
        if not domains:
            print(f"Error: Could not read file {args.l}")
            sys.exit(1)

        for domain in domains:
            handle_domain_check(domain, args.o, append=False)
            handle_tenant_check(domain, args.o, append=True)

if __name__ == "__main__":
    main()


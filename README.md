# AZFINDER
az-finder is a tool for enumerating Azure Active Directory (Azure AD, also known as Entra ID) domains and tenant information. This script fetches related domains and tenant details for a given domain or a list of domains.

## Features
* Retrieves related domains for a given Azure AD domain.
* Fetches tenant information including Tenant ID, Federation Brand Name, Region, Namespace Type, and SSO URL.
* Supports output to both .html and .txt file formats.

## How to Install
Clone the Repository
To get started, clone the repository to your local machine:

```
pip install -r requirements.txt
```
This will install the following Python libraries:
- requests: For making HTTP requests.
- tabulate: For generating formatted tables in terminal or text files.

## Usage
```
python3 az-finder.py [options]

 AAAAA   ZZZZZZZ  FFFFFF  IIIII  N   N  DDDDD  EEEEE  RRRRR 
A     A      Z    F         I    NN  N  D    D E      R    R
AAAAAAA     Z     FFFFF     I    N N N  D    D EEEEE  RRRRR 
A     A    Z      F         I    N  NN  D    D E      R  R  
A     A  ZZZZZZZ  F       IIIII  N   N  DDDDD  EEEEE  R   RR

by timothians Shebin Mathew

usage: az-finder.py [-h] [-d D] [-l L] [-o O]

az-finder is a tool for enumerating Azure AD (Entra ID) domains and tenant information.

options:
  -h, --help  show this help message and exit
  -d D        Domain to find information about
  -l L        File containing list of domains
  -o O        File to write output (supports .txt or .html files)


```
#### Options:

- -d: The domain to find information about.
- -l: A file containing a list of domains (one domain per line).
- -o: Output file to write results to. Supported file formats are .txt or .html.

## Examples
#### Fetching Information for a Single Domain
```
python3 az-finder.py -d example.com
```
#### Fetching Information for Multiple Domains from a File
```
python3 az-finder.py -l domains.txt
```
#### Outputting the Results to a File
- To output the results in a text file:
```
python3 az-finder.py -d example.com -o output.txt
```
- To output the results in an HTML file:
```
python3 az-finder.py -d example.com -o output.html

```
## Example Output 
When output is written to a text file:

```
[*] Domains related to example.com:
+------------------------+
| Related Domains        |
+------------------------+
| mail.example.com       |
| login.example.com      |
| autodiscover.example.com|
+------------------------+

[*] Tenant information for domain example.com:
+------------------+----------------------------+
| Tenant Info      | Details                    |
+------------------+----------------------------+
| Tenant Brand Name| Example Corporation         |
| Tenant ID        | 12345678-1234-1234-1234-123 |
| Tenant Region    | EU                          |
| Namespace Type   | Managed                     |
| Auth URL (SSO)   | https://login.microsoft.com |
+------------------+----------------------------+
```
#### Notes
- This script uses the Azure Autodiscover service to fetch related domains and the Azure OpenID Connect configuration to retrieve tenant information.
- If Azure services are temporarily unavailable or the domain is not associated with Azure, the script may return partial or no data.

#azure
#subdomain-enumeration
#azure-security
#Security tool

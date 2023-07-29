# CVE-2023-35078 Exploit POC
CVE-2023-35078 Remote Unauthenticated API Access vulnerability has been discovered in Ivanti Endpoint Manager Mobile (EPMM), formerly known as MobileIron Core. This vulnerability impacts all supported versions – Version 11.4 releases 11.10, 11.9 and 11.8. Older versions/releases are also at risk.
This vulnerability enables an unauthorized, remote (internet-facing) actor to potentially access users’ personally identifiable information and make limited changes to the server.

## Usage
```
python cve_2023_35078_poc.py -u http://
python cve_2023_35078_poc.py -f urls.txt
```


https://github.com/vchan-in/CVE-2023-35078-Exploit-POC/assets/17123227/2817fcd5-4399-4c88-82b3-de1c03b3be24



## References
- https://nvd.nist.gov/vuln/detail/CVE-2023-35078
- https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability	
- https://forums.ivanti.com/s/article/KB-Remote-unauthenticated-API-access-vulnerability-CVE-2023-35078	
- https://www.cisa.gov/news-events/alerts/2023/07/24/ivanti-releases-security-updates-endpoint-manager-mobile-epmm-cve-2023-35078	
- https://www.ivanti.com/blog/cve-2023-35078-new-ivanti-epmm-vulnerability

import requests
import sys

# function to check if the website is vulnerable to any known vulnerabilities
def check_vulnerabilities(website):
  # list of known vulnerabilities
  vulnerabilities = ["CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003"]
  
  # check if the website is vulnerable to any of the known vulnerabilities
  for vulnerability in vulnerabilities:
    response = requests.get(website + "/" + vulnerability)
    if response.status_code == 200:
      print("Website is vulnerable to " + vulnerability)
    else:
      print("Website is not vulnerable to " + vulnerability)

# get the website to check from the command line argument
website = sys.argv[1]

# check if the website is vulnerable to any known vulnerabilities
check_vulnerabilities(website)

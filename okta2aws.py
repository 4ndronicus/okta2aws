import json, requests, base64, xmltodict, urllib.parse
import sys
from bs4 import BeautifulSoup

#******************************************************************************
#
# Function Name:  oktaAuth
# By: Scott Morris <smmorris@gmail.com>
# Date: 2021-09-24
#
# Description: Authenticates against the specified okta server with the
#   provided username and password
#
# Required imports:
#   o import json - to convert between json and dictionary formats
#   o import requests - to perform the HTTPS request
#
# Prerequisites: None
#
# Post-conditions:
#   o We have the session token available for the next step
#
# Expected parameters:
#   o username - string - the username of the account in okta
#   o password - string - the password of the account in okta
#   o oktaUrl - string - the URL of the okta server (https://okta.example.com/)
#
# Returns:
#   o the session token - string
#
# Usage Example:
# 
# sessionToken = oktaAuth(username,password,oktaUrl)
#
#******************************************************************************

def oktaAuth(username,password,oktaUrl):

    # Assemble the url that we'll authenticate to OKTA with
    oktaAuthUrl = oktaUrl + "/api/v1/authn"

    # Include the Content-Type header to specify that we're sending json
    headerDict = { "Content-Type": "application/json; charset=utf-8" }

    # Format the username and password into a json string
    oktaCreds = json.dumps({ "username":username, "password":password })

    # Make the call, grab the response
    response = requests.post( oktaAuthUrl, headers=headerDict, data=oktaCreds)

    # Return the session token
    return response.json()['sessionToken']

#******************************************************************************
#
# Function Name: oktaGetSamlResponse
# By: Scott Morris <smmorris@gmail.com>
# Date: 2021-09-24
#
# Description: Uses the provided URLs and session token to retrieve the SAML
#   response from the Okta server.
#
# Required imports:
#   o import requests - to perform the HTTPS requests
#   o from bs4 import BeautifulSoup - for traversing the DOM in HTML
#   o import urllib.parse - for url-encoding a string
#
# Prerequisites:
#   o Must have already authenticated against okta
#
# Post-conditions: None
#
# Expected parameters:
#   o oktaUrl - string - the URL of the Okta IDP in the format: https://<fqdn>/
#
# Returns:
#   o samlResp - string - base64 encoded string containing the response from the
#       okta server
# 
# Usage Example:
#
# samlb64enc = oktaGetSamlResponse(oktaUrl,sessionToken,oktaForwardUrl)
#
#******************************************************************************

def oktaGetSamlResponse(oktaUrl,sessionToken,oktaForwardUrl):

    # Build the URL we're going make our request to
    samlUrl = oktaUrl + "/login/sessionCookieRedirect?checkAccountSetupComplete=true&token="

    # Make the request, grab the response
    samlAuth = requests.get(samlUrl + sessionToken + "&redirectUrl=" + oktaForwardUrl)

    # Make a traversible object we can use to find the SAML response
    bs = BeautifulSoup(samlAuth._content.decode(),features="html.parser")

    # Pull out and grab the SAML response
    samlResp = bs.find("input", {"name": "SAMLResponse"})['value']

    # URL-decode and return the saml response - it is base64-encoded
    return urllib.parse.unquote(samlResp)

#******************************************************************************
#
# Function Name: awsAssumeRole
# By: Scott Morris <smmorris@gmail.com>
# Date: 2021-09-24
#
# Description: Connects to AWS to assume a role and gives us back the
#   credentials for future calls to AWS under the role assumption.
#
# Required imports:
#   o import xmltodict - for converting XML to a dictionary
#   o import base64 - to base64 encode/decode strings
#   o import urllib.parse - for url-encoding/decoding a string
#   o import requests - to perform the HTTPS requests
#   o import xmltodict - for converting XML to  dictionary
#
# Prerequisites:
#   o Must have authenticated to the okta server, retrieved the session token,
#       and retrieved the saml response from the okta server.
#
# Post-conditions:
#   o The role has been assumed in AWS
#   o The calling function now has the credentials needed to perform additional
#       operations in AWS using the role assumption
#
# Expected parameters:
#   o samlb64enc - string - the SAML response from the okta server. Must be
#       base64 encoded.
#
# Returns:
#   o AWS role assumption credentials as a dictionary
#
# Usage Example:
#
# creds = awsAssumeRole(samlb64enc)
#
#******************************************************************************

def awsAssumeRole(samlb64enc):

    # Base64-decode the SAML response, convert it from XML to a dictionary
    arnDict = xmltodict.parse(base64.b64decode(samlb64enc))

    # Find the value that contains the role ARN and the principal ARN
    arnStr = arnDict['saml2p:Response']['saml2:Assertion']['saml2:AttributeStatement']['saml2:Attribute'][0]['saml2:AttributeValue']['#text']

    # Grab the role ARN
    roleArn = arnStr.split(",")[1]

    # Grab the principal ARN
    principalArn = arnStr.split(",")[0]

    # Build our URL that we're going to use to make the role assumption
    awsReqUrl = "https://sts.amazonaws.com/?Version=2011-06-15&Action=AssumeRoleWithSAML&RoleArn=" + roleArn + "&PrincipalArn=" + principalArn + "&SAMLAssertion=" + urllib.parse.quote_plus(samlb64enc)

    # Make the request, grab the response as an XML string
    awsXml = requests.get(awsReqUrl)._content.decode()

    # Convert the XML string into a dictionary
    awsDict = xmltodict.parse(awsXml)

    # Return the credentials from the response
    return awsDict['AssumeRoleWithSAMLResponse']['AssumeRoleWithSAMLResult']['Credentials']

#******************************************************************************
#
# Function Name: getOktaUrl
# By: Scott Morris <smmorris@gmail.com>
# Date: 2021-09-24
#
# Description: Analyzes a URL. Returns <protocol>://<fqdn> of URL.
#
# Required imports:
#   import urlib.parse - for parsing the URL
#
# Prerequisites: None
#
# Post-conditions: None
#
# Expected parameters:
#   o fullUrl - string - contains a URL to parse
#
# Returns:
#   o protocol and fully-qualified domain name - string - format shown above
#
# Usage Example:
#
# baseUrl = getOktaUrl(fullUrl)
#
#******************************************************************************

def getOktaUrl(fullUrl):

    # Get the 6-tuple of the full URL broken down into components
    urlTuple = urllib.parse.urlparse(fullUrl)

    # Return the protocol and fqdn - looks like https://www.myserver.com
    return urlTuple.scheme + "://" + urlTuple.netloc

#******************************************************************************
#
# Function Name: assume
# By: Scott Morris <smmorris@gmail.com>
# Date: 2021-09-24
#
# Description: Authenticates against the Okta SAML IDP, retrieves the necessary
#   credentials, and authenticates against AWS to assume the role.
# 
# Required imports:
#   o import json - to convert between json and dictionary formats
#   o import requests - to perform the HTTPS requests
#   o import base64 - to base64 encode/decode strings
#   o import xmltodict - for converting XML to a dictionary
#   o import urllib.parse - for url-encoding/decoding a string
#   o from bs4 import BeautifulSoup - for traversing the DOM in HTML
#
# Prerequisites:
#   o Role must be already created in AWS
#   o Account must already exist in the SAML IDP
#   o System executing script must be able to reach the Okta provider
#   o System executing script must be able to reach AWS
#
# Post-conditions:
#   o The script has assumed the role in AWS
#   o We have the credentials needed to communicate with AWS
#
# Expected parameters:
#   o username - string - the username of the account in Okta
#   o password - string - the password of the account in Okta
#   o oktaForwardUrl - string - the URL associated in Okta with the AWS account
#       to use when logging in
#   o oktaUrl - string - the URL of the Okta IDP in the format: https://<fqdn>/
#
# Returns:
#   o creds - dictionary - the credentials needed to run commands against the
#       AWS account using the assumed role. This information is used in future
#       operations in AWS with this role assumption.
#
# Usage Example:
#
# un = input("PID Username: ")
# pw = getpass.getpass("PID Password: ") # requires import of getpass
# acctUrl = "https://okta.example.com/home/amazon_aws/0oa3notarealurl490x7/272"
# oktaUrl = "https://okta.example.com"
# creds = assume(un,pw,acctUrl,oktaUrl)
# print(creds)
#
#******************************************************************************

def assume(username,password,oktaForwardUrl):

    # Pull the protocol and fqdn out of the okta url - like https://server.com
    oktaUrl = getOktaUrl(oktaForwardUrl)

    # Retrieve the session token
    sessionToken = oktaAuth(username,password,oktaUrl)

    # Retrieve the base64-encoded SAML response from the OKTA server
    samlb64enc = oktaGetSamlResponse(oktaUrl,sessionToken,oktaForwardUrl)

    # Return the role assumption credentials from AWS
    return awsAssumeRole(samlb64enc)


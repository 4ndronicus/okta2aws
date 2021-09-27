# okta2aws
Allows you to authenticate against an OKTA server and then assume a role in AWS.

## Assumptions ##
The following assumptions are made:
1. You are authenticating against an OKTA server.
1. You have created an account in OKTA that you wish to use to assume roles in AWS.
1. You have created a role to assume in AWS.
1. You have given permission to the OKTA user to assume the role in AWS.
1. You have the required modules installed.

## Required Modules ##
The following imports are required for this one to work properly:
```
import json
import requests
import base64
import xmltodict
import urllib.parse
import sys
from bs4 import BeautifulSoup
```
If any are missing, install them with:
```
pip install <module name>
```

## Usage ##
1. Import the module.
1. You will then need 3 things to call the module:
   1. OKTA username
   1. OKTA password
   1. OKTA user URL
1. Call the 'assume' function

```
import okta2aws

# You will then prompt user for OKTA username, password, and URL

sessionCredentials = okta2aws(username,password,oktaUrl)
```
Then, you can use those credentials to perform AWS calls.

If you are not aware already, AWS interaction is done with boto.

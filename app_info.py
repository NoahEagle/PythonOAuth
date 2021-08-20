# Was this just used to auto-fill ID/Secret from Azure AD site when pressing the "do it for me" button?
import os

# Client ID obtained from Overview page for Replica Tester App on Azure AD
CLIENT_ID = "af0581ee-6d10-4df5-aaff-c539518339a4"

# Client certificate information (we'll calculate the private key, and also the thumbprint if we want, when we create a CCA)
CLIENT_CERTIFICATE_THUMBPRINT = "91C3BC74995492886C972BB066189E6BFFC845ED"
CLIENT_CERTIFICATE_PASSPHRASE = "1234"
CLIENT_CERTIFICATE_LOCATION = "C:/Users/n_eagle/test.crt"
CLIENT_CERTIFICATE_PRIVATE_KEY_LOCATION = "C:/Users/n_eagle/test.key"

# Client secret was originally obtained from Azure AD
CLIENT_SECRET = "NgC~L0Pj-xF6RyPj8A~5FhX_GL-9G.I27l"

# After we get an auth code, we'll redirect here to then request a token
REDIRECT_PAGE = "/tokentime"

# For a multi-tenet app
#AUTHORITY = "https://login.microsoftonline.com/common/"

AUTHORITY = "https://login.microsoftonline.com/consumers/"

# The location of the resource we want information from after successful authentication
RESOURCE_LOCATION = "https://graph.microsoft.com/v1.0/users"

# The permissions we'll have after successful authentication
SCOPE = ["User.ReadBasic.All", "xboxlive.signin", "xboxlive.offline_access"]

# Only the MS Graph related scope
SCOPE_GRAPH = ["User.ReadBasic.All"]

# Only the XBL related scopes
SCOPE_XBL = ["xboxlive.signin", "xboxlive.offline_access"]

# So the token cache will be stored in the server-side session
SESSION_TYPE = "filesystem"
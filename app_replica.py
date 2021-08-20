# What is uuid for? It doesn't look like it's used anywhere
import re
import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
import msal
from requests.api import head
import app_info
import json
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import argparse

# Instantiate an instance of the Flask class called app
app_replica = Flask(__name__)

# Load in the info/fields from app_info
# But what does that mean? We still have to call app_info's fields via app_info.FIELD like if we had only done import app_info
app_replica.config.from_object(app_info)

# And now start a session with this app
Session(app_replica)

# This is apparently necessary for the url_for() function to work properly on localhost
from werkzeug.middleware.proxy_fix import ProxyFix
app_replica.wsgi_app = ProxyFix(app_replica.wsgi_app, x_proto=1, x_host=1)

# When we're on the homepage: http://localhost:5000/, run this function
@app_replica.route("/")
def home():
    # If our session has no active signed in user, then redirect them to the sign in page and run that sign in function
    if session.get("user") == None:
        return redirect(url_for("signin"))
    # If we do have a signed in user, show them the index.html template which has options to call MS Graph API and log out
    else:
        return render_template("index.html", user = session["user"], version = msal.__version__)

# When we're on the sign in page: http://localhost:5000/signin, run this function
@app_replica.route("/signin")
def signin():
    # Start the auth code request process (not sure exactly what that means)
    session["flow"] = createAuthCodeFlow(scopes = app_info.SCOPE)

    # Now display the login.html template which has a sign in button waiting to be pressed
    return render_template("login.html", auth_url = session["flow"]["auth_uri"], version = msal.__version__)

# When we're on the tokentime page (which we go to after user sign in): http://localhost:5000/tokentime, run this function
@app_replica.route("/tokentime")
def verified():
    try:

        # Load up our session's token cache
        token_cache = loadTokenCache()

        # Create a CCA and then get a token via auth code
        # request.args gives values from the query string (and I'm assuming auth code is given in query string when logging in with MS)
        result = createCCA(token_cache = token_cache).acquire_token_by_auth_code_flow(session.get("flow", {}), request.args, scopes = app_info.SCOPE_GRAPH)

        print("This contains the authorization code...")
        print(request.args)

        # Why is this different than the access token we use to get Graph info (no way this expired by then so it should be the same)
        print("Initial Access Token (Should be Graph-only)...")
        print(result)

        # If acquire_token_by_auth_flow gave us a dict with an "error" key, we failed authentication and didn't get a token
        if "error" in result:
            return render_template("auth_error.html", result = result)

        # Save the session user as their username or special user ID???
        session["user"] = result.get("id_token_claims")

        # Save the token cache now that we've added newly acquired tokens
        # Although when are the tokens actually added to the cache? The acquire_token_by_auth_code_flow function just returns a dict
        # with the tokens, it doesn't say that it adds the tokens to the cache
        saveTokenCache(token_cache)

    # If we get an error, do nothing I guess
    except ValueError:
        pass

    # Now that we have a valid access token, we can use it to request a user token
    userToken = fetchUserToken()

    # Now that we have a valid user token, we can use it to request an X Token
    if userToken:
        xToken = fetchXToken(U_Token = userToken)

    # Now that we have a valid X token, we can use it to make calls to Xbox Live Services (and get achievements for example)
    if xToken:
        getAchievements(xToken)
        getFriendsList(xToken)
        getUserStats(xToken)

    # Now that they're finally fully authenticated, send them to the main page where they can call MS Graph API or log out
    return redirect(url_for("home", user=session["user"], version=msal.__version__))

@app_replica.route("/logout")
def logout():

    # Clears cache and user info from this session (locally I think)
    session.clear()

    # Then this clears the cache and user info from the tenet's web session (so that both sides local and tenet cleared)
    return redirect(app_info.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("home", _external=True))

@app_replica.route("/graphcall")
def graphcall():

    # Try and grab an access token for Graph from the cache
    access_token = grabTokenFromCache(app_info.SCOPE_GRAPH)

    # If we did get a token (because token isn't None),
    if access_token:

        # Request info from the resource location we have permisson for
        graph_response = requests.get(app_info.RESOURCE_LOCATION, headers = {"Authorization": "Bearer " + 
        access_token["access_token"]}).json()

        # Why is this different every time? Is acquireTokenSilent auto refreshing on each call? It shouldn't be
        print("This is the used access token for a Graph call...")
        print(access_token)

        # Display the received info from Graph on the screen
        return render_template("display.html", result = graph_response)

    # Assuming we didn't get a token
    else:
        
        # Redirect the user to the sign-in page/function
        return redirect(url_for("signin"))

# Grab a token from the cache (if one exists)
def grabTokenFromCache(scope = None):

    # Load up the token cache and store it in token_cache
    token_cache = loadTokenCache()

    # Create a CCA using this token cache
    cca = createCCA(token_cache = token_cache, authority = app_info.AUTHORITY)

    # Grab all the accounts that are currently signed in
    accounts = cca.get_accounts()

    # If accounts was non-empty (meaning someone's signed in)
    if accounts:

        # Get a token for this account
        result = cca.acquire_token_silent(scopes = scope, account = accounts[0], force_refresh = False)

        # Save that token cache
        saveTokenCache(token_cache)

        # Return the dict returned by acquire_token_silent (which has the access token on success or None if it failed)
        return result

    # If there were no signed in accounts, just return None (we'll get no token)
    return None

# If the token cache has been altered since last save, convert it into JSON string form and store it in session["token_cache"]
def saveTokenCache(token_cache):
    if token_cache.has_state_changed:
        session["token_cache"] = token_cache.serialize()

# Load up the token cache (or create one if we don't have one)
def loadTokenCache():

    # Get a fresh token cache?
    token_cache = msal.SerializableTokenCache()

    # If we already have a token cache in this session, then convert it into an object and store it in token_cache
    if session.get("token_cache"):
        token_cache.deserialize(session["token_cache"])

    # Now return the token cache (either a new empty one or the one we've been working with if we had one)
    return token_cache

# Create a Confidential Client App based on the client ID and secret, where authority corresponds to who's allowed to be 
# authenticated, and our token cache is the cache we've created in this program
def createCCA(token_cache = None, authority = None):
    
    # Create a command line argument parser
    parser = argparse.ArgumentParser(description = "Authenticate user with Microsoft account")

    # Add an optional argument --cert that can be included in the command line that will make cert = True if appears, False otherwise
    # (This way if cert = True, we can use certificate code, otherwise use secret code)
    parser.add_argument("--cert", action = "store_true", help = "Use a certificate for authorization (default: use a secret)")

    # Actually get the arguments from the command line and store them
    args = parser.parse_args()

    # If the cert argument was present (meaning cert = True), use a certificate for authorization
    if args.cert:

        print("We used a certificate")

        # Reads the private key from its file stored locally and saves it
        with open(app_info.CLIENT_CERTIFICATE_PRIVATE_KEY_LOCATION) as file:
            private_key = file.read()

        # Reads the certificate from its file stored locally and saves it. (Looks like it's needed to get the thumbprint without hardcoding)
#       with open(app_info.CLIENT_CERTIFICATE_LOCATION) as file:
#           public_certificate = file.read()

        # Creates a x509 container for the certificate??? (Looks like it's needed to get the thumbprint without hardcoding)
#       cert = load_pem_x509_certificate(data = bytes(public_certificate, 'UTF-8'), backend = default_backend())

        # Grabs the certificate's thumbprint (in case you don't want to hardcode it in app_info.py)
#       thumbprint = cert.fingerprint(hashes.SHA1()).hex()

        return msal.ConfidentialClientApplication(client_id = app_info.CLIENT_ID, client_credential = {"private_key": private_key, 
        "thumbprint": app_info.CLIENT_CERTIFICATE_THUMBPRINT, "passphrase": app_info.CLIENT_CERTIFICATE_PASSPHRASE}, 
        authority = authority or app_info.AUTHORITY, token_cache = token_cache)

    # Otherwise, use a secret for authorization
    else:

        print("We used a secret")

        return msal.ConfidentialClientApplication(client_id = app_info.CLIENT_ID, client_credential = app_info.CLIENT_SECRET, 
        authority = authority or app_info.AUTHORITY, token_cache = token_cache)

# Start the auth code flow by creating a CCA and then starting the auth code flow process (not sure what that exactly means)
def createAuthCodeFlow(authority = None, scopes = None):
    return createCCA(authority = authority).initiate_auth_code_flow(scopes or [], 
    redirect_uri = url_for("verified", _external = True))

# Use a valid access token to request a user token. If we get one, return it. If we can't, return None
def fetchUserToken():

    # Set the required headers for the POST to XASU for a User Token
    myHeaders = {
        "x-xbl-contract-version": "3.2", # White Papers had it as 0, but a more recent MS doc said they were on version 3.2
        "Content-Type": "application/json"
    }

    # Try and grab an access token (as we'll need one to request a user token)
    access_token = grabTokenFromCache(app_info.SCOPE)

    print("This is the used access token for user token request...")
    print(access_token)

    # If we didn't get an access token, send the user to the signin page so we can get another access token
    if not access_token:
        return redirect(url_for("signin"))

    # Set the body for the POST according to the required data contract for XASU
    myJSON = {
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": "d=" + access_token["access_token"]
        }
    }

    # Now make a post request to the XASU REST endpoint with the required headers and correct body to receive a user token
    response = requests.post("https://user.auth.xboxlive.com/user/authenticate", json = myJSON, headers = myHeaders)

    # Assuming we got a successful 200 status code, we have a valid user token, so return it
    if response.status_code == 200:
        print("User token content...")
        print(response.content) # Only here so we can see the user token upon success
        return response
    # And if we did hit an error, print out which error we hit for learning purposes (but return None)
    else:
        print("User token status code...")
        print(response.status_code)
        return None

# Use a previously receieved User Token to request an X Token. If we receive one, return it. If we can't, return None
def fetchXToken(U_Token = None):

    # Put the user token into JSON form
    loaded_U_Token = U_Token.json()

    # Set the required headers for the POST to XSTS for an X Token
    myHeaders = {
        "x-xbl-contract-version": "1", # Might need to update to 3.2 or whatever they're on currently if this is outdated info
        "Content-Type": "application/json"
    }

    # Set the body for the POST according to the required data contract for XSTS
    myJSON = {
        "RelyingParty": "http://xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "UserTokens": [loaded_U_Token["Token"]],
            "SandboxId": "RETAIL"
        }
    }

    # Now make a POST request to the XSTS REST endpoint with the required headers and body to receive an X Token
    response = requests.post("https://xsts.auth.xboxlive.com/xsts/authorize", json = myJSON, headers = myHeaders)

    # Assuming we got a successful 200 status code, we got a valid X Token, so return it
    if response.status_code == 200:
        print("X token content...")
        print(response.content) # Just printing for visualization purposes
        return response

    # If we did fail, just print out the error code and return None
    else:
        print("X token status code...")
        print(response.status_code)
        return None

# Uses valid X token to get user's xbox achievements
def getAchievements(X_Token = None):

    # Put the X token into JSON form
    loaded_X_Token = X_Token.json()

    # Get the user hash associated with this X token
    userHash = loaded_X_Token["DisplayClaims"]["xui"][0]["uhs"]

    # Get the value associated with this X token
    xToken_val = loaded_X_Token["Token"]

    # Set the required header for an achievement GET call
    myHeaders = {
        "Authorization": "XBL3.0 x=" + userHash + ";" + xToken_val, # Form: "XBL3.0 x=<userHash>;<XToken>"

        "x-xbl-contract-version": "2" # 2 or 4 for XB1 games (Series X/S too?) and 1 or 3 for 360 games
    }

    # Get the XUID (Xbox User ID) associated with this X token
    XUID = loaded_X_Token["DisplayClaims"]["xui"][0]["xid"]

    # Assemble the url we do the GET from with the user specific XUID in the ()
    chieveLink = "https://achievements.xboxlive.com/users/xuid(" + XUID + ")/achievements"
    
    myParams = {
        "titleId": "840116976", # The Title ID for World of Tanks
        "unlockedOnly": True # Means only return the unlocked achivements
    }
    
    # Make the GET request to the achievement url with the required header (and optional query string params)
    response = requests.get(url = chieveLink, headers = myHeaders, params = myParams)

    # If we got a successful 200 status code, then we should've gotten user achievements, so return them
    if response.status_code == 200:
        print("This is the achievement call response...")
        print(response.content) # This is just here so we can see the achievements we're getting
        return response

    # Otherwise, we failed and got an error, so print out the error code and return None
    else:
        print("This is the achivement status code...")
        print(response.status_code)
        return None

# Uses valid X token to get user's friends list
def getFriendsList(X_Token = None):

    # Convert the X token into its JSON form
    loaded_X_Token = X_Token.json()

    # Obtain the user's XUID (Xbox User ID) from the X token
    XUID = loaded_X_Token["DisplayClaims"]["xui"][0]["xid"]

    # Complete the link for the friends list GET with the obtained XUID
    friendsLink = "https://social.xboxlive.com/users/xuid(" + XUID + ")/people"

    # Obtain the user hash from the X token
    userHash = loaded_X_Token["DisplayClaims"]["xui"][0]["uhs"]

    # Obtain the X token's value
    xToken = loaded_X_Token["Token"]

    # Set the required Authorization header with the obtained user hash and token values
    myHeaders = {
        "Authorization": "XBL3.0 x=" + userHash + ";" + xToken # Form: "XBL3.0 x=<userHash>;<XToken>"
    }

    # Make the actual GET call to the link with the specified XUID and the required Authorization header
    response = requests.get(url = friendsLink, headers = myHeaders)

    # If we were successful with a 200 status code, then we should've gotten a friends list, so return it
    if response.status_code == 200:
        print("Here is the obtained friends list...")
        print(response.content)
        return response

    # Otherwise, we failed and should print out the status code and return None
    else:
        print("Here's the friends list status code...")
        print(response.status_code)
        return None

# Use a valid X Token to get various user statistics
def getUserStats(X_Token = None):
    
    # Convert the X token into JSON form
    loaded_X_Token = X_Token.json()

    # Grab the User's Xbox User ID from the X token
    XUID = loaded_X_Token["DisplayClaims"]["xui"][0]["xid"]

    # The Service Configuration ID for World of Tanks found in Partner Center
    SCID = "3a660100-4a3c-4d9f-9aa6-0ab532132af0"

    # A list of desired stats (eligible stats can be found in Partner Center)
    stats_list = "TotalXPEarned,TotalTanksUnlocked"

    # Generate the url for the GET request using the obtained XUID, SCID, and list of desired stats
    statsLink = "https://userstats.xboxlive.com/users/xuid(" + XUID + ")/scids/" + SCID + "/stats/" + stats_list

    # Grab the user hash value from the X token
    userHash = loaded_X_Token["DisplayClaims"]["xui"][0]["uhs"]

    # Grab the token value from the X token
    xTokenVal = loaded_X_Token["Token"]

    # Use the user hash and token values from the X token to create the required Authorization header
    myHeaders = {
        "Authorization": "XBL3.0 x=" + userHash + ";" + xTokenVal # Form: "XBL3.0 x=<userHash>;<xToken>"
    }

    # Do the GET request to the the link with the required header
    response = requests.get(statsLink, headers = myHeaders)

    # If we received a successful status code of 200, then we should've received the user stats, so return them
    if response.status_code == 200:
        print("Here are the obtained user statistics...")
        print(response.content)
        return response
    # Otherwise, we failed and should return None and print out what the error status code was
    else:
        print("Here is the user statistics status code...")
        print(response.status_code)
        return None

# Initialization process for requesting auth codes???
app_replica.jinja_env.globals.update(_build_auth_code_flow=createAuthCodeFlow)  # Used in templates somehow???

# This way, when we execute the program directly, it'll run
if __name__ == "__main__":
    app_replica.run(debug = True, use_reloader = False)
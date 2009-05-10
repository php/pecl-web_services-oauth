#!/usr/bin/env php
<?php
require("config.inc.php");
try {
	$oauth = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_URI);

	/* Google scopes are in the following format: urlencoded(scope) urlencoded(scope) */
	$scopes = urlencode("http://www.google.com/calendar/feeds/") . "%20" . urlencode("http://www.blogger.com/feeds/") . "%20" . urlencode("http://www-opensocial.googleusercontent.com/api/people/");

    $request_token_info = $oauth->getRequestToken(GOOGLE_OAUTH_REQUEST_TOKEN_API . "?scope={$scopes}");

    printf("Request token: %s\n",$request_token_info["oauth_token"]);
    printf("Request token secret: %s\n\n",$request_token_info["oauth_token_secret"]);

    printf("I think I got a valid request token, navigate your www client to:\n\n%s?oauth_token=%s\n\nOnce you finish authorizing, hit ENTER or INTERRUPT to exit\n", GOOGLE_OAUTH_AUTHORIZE_API, $request_token_info["oauth_token"]);

    $in = fopen("php://stdin", "r");
    fgets($in, 255);

    $oauth->setToken($request_token_info["oauth_token"],$request_token_info["oauth_token_secret"]);

    /* grab the access token, which is your persistent token which you use for future requests */
    printf("Grabbing an access token...\n");
	$access_token_info = $oauth->getAccessToken(GOOGLE_OAUTH_ACCESS_TOKEN_API);

    printf("Access token: %s\n",$access_token_info["oauth_token"]);
    printf("Access token secret: %s\n\n",$access_token_info["oauth_token_secret"]);

    printf("Fetching contacts in JSON via %s\n",GOOGLE_POCO_CONTACT_INFO_API);
    $oauth->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

    /* put the OAuth params into the Authorization header */
    $oauth->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);
    $oauth->fetch(GOOGLE_POCO_CONTACT_INFO_API);

    /* from this point on OAuth is over, now handling the JSON response is in order */
    $json = json_decode($oauth->getLastResponse());
    printf("My contact information at Google: \nGiven name: %s\nFamily name: %s\nDisplay name: %s\n\n",$json->entry->name->givenName,$json->entry->name->familyName,$json->entry->displayName);

    printf("Fetching all of {$json->entry->displayName}'s contacts in JSON via %s\n",GOOGLE_POCO_ALL_CONTACTS);
    $oauth->fetch(GOOGLE_POCO_ALL_CONTACTS);
    $json = json_decode($oauth->getLastResponse());

    printf("=== Total contacts: %d, showing: %d-%d ===\n",$json->totalResults,$json->startIndex+1,sizeof($json->entry));

    foreach($json->entry as $n => $contact_object) {
        printf("#%d: %s\n",$n+1,$contact_object->displayName);
    }
} catch(OAuthException $E) {
	echo "[EXCEPTION] Response: ". $E->lastResponse . "\n";
	echo "[EXCEPTION] More Info: ". $E . "\n";
}


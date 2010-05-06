<?php

/* specify oauth params in this array if you are using the CLI sapi...for unit tests maybe... oauth_bar => foo */
if(PHP_SAPI=="cli") {
	$params = array("oauth_token" => "a_good_token", "oauth_timestamp" => "12345", "oauth_nonce" => "raNdOM", "oauth_consumer_key" => "api_key", "oauth_signature" => "invalid", "oauth_signature_method" => OAUTH_SIG_METHOD_HMACSHA1);
} else {
	$params = array();
}

function lookupConsumer($provider) {
	if($provider->consumer_key=="unknown") {
		return OAUTH_CONSUMER_KEY_UNKNOWN;
	} else if($provider->consumer_key=="blacklisted" || $provider->consumer_key=="throttled") {
		return OAUTH_CONSUMER_KEY_REFUSED;
	}
	$provider->consumer_secret = "the_consumers_secret";

	/* we must have the caller send us a callback for 1.0a ... addRequiredParameter takes any parameter name and reports it as part of
	 * OAuthProvider::reportProblem() */
	$provider->addRequiredParameter("oauth_callback");

	/* changed our mind heh */
	$provider->removeRequiredParameter("oauth_callback");
	return OAUTH_OK;
}

function timestampNonceChecker($provider) {
	if($provider->nonce=="bad") {
		return OAUTH_BAD_NONCE;
	} else if($provider->timestamp=="0") {
		return OAUTH_BAD_TIMESTAMP;
	}
	return OAUTH_OK;
}

function tokenHandler($provider) {
	if($provider->token=="rejected") {
		return OAUTH_TOKEN_REJECTED;
	} else if($provider->token=="revoked") {
		return OAUTH_TOKEN_REVOKED;
	}

	$provider->token_secret = "the_tokens_secret";
	return OAUTH_OK;
}

/* Problem Reporting constants supported (can be returned from any callback)
 * OAUTH_BAD_TIMESTAMP
 * OAUTH_BAD_NONCE
 * OAUTH_CONSUMER_KEY_UNKNOWN
 * OAUTH_CONSUMER_KEY_REFUSED
 * OAUTH_TOKEN_USED
 * OAUTH_TOKEN_EXPIRED
 * OAUTH_TOKEN_REVOKED
 * OAUTH_TOKEN_REJECTED
 * OAUTH_VERIFIER_INVALID
 * OAUTH_INVALID_SIGNATURE
 * OAUTH_PARAMETER_ABSENT
 * check out http://wiki.oauth.net/ProblemReporting for more info
 */

?>

<?php
include('common.inc.php');

try {
	$provider = new OAuthProvider($params);

	/* the 2-legged flow, or request signing, doesn't require a token, of course you can always require one in which case don't use is2LeggedEndpoint */
	$provider->is2LeggedEndpoint(true);

	/* OAuthProvider will call this callback with the $provider object as an argument, you can throw errors from that handler and set the $provider->consumer_key if all is good */
	$provider->consumerHandler('lookupConsumer');

	/* similar to consumerHandler, throw errors related to the timestamp/nonce in this callback */
	$provider->timestampNonceHandler('timestampNonceChecker');

	/* this is the meat of request authorization, the first argument is the URL of this endpoint as the outside world sees it
	 * the optional second argument is the HTTP method, GET, POST, etc ... the provider will try to detect this via $_SERVER["REQUEST_METHOD"] (usually reliable) when it's not set */
	$provider->checkOAuthRequest("http://localhost/request_signing.php", PHP_SAPI=="cli" ? OAUTH_HTTP_METHOD_GET : NULL);

} catch (OAuthException $E) {

	/* when you catch OAuthException and echo OAuthProvider::reportProblem with it, you'll get the problem reporting extension described here:
	 * http://wiki.oauth.net/ProblemReporting for free, it also sets the most appropriate HTTP response code */
	echo OAuthProvider::reportProblem($E);
}

?>

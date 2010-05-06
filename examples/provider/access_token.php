<?php
include('common.inc.php');

try {
	$provider = new OAuthProvider($params);

	$provider->consumerHandler('lookupConsumer');

	$provider->timestampNonceHandler('timestampNonceChecker');

	$provider->tokenHandler('tokenHandler');

	$provider->checkOAuthRequest("http://localhost/access_token.php", PHP_SAPI=="cli" ? OAUTH_HTTP_METHOD_GET : NULL);

} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

?>

<?php
include('common.inc.php');

try {
	$provider = new OAuthProvider($params);

	$provider->your_own_member = "this is passed to every callback";

	$provider->consumerHandler('lookupConsumer');

	$provider->timestampNonceHandler('timestampNonceChecker');

	$provider->tokenHandler('tokenHandler');

	$provider->checkOAuthRequest("http://localhost/a_private_api.php", PHP_SAPI=="cli" ? OAUTH_HTTP_METHOD_GET : NULL);

} catch (OAuthException $E) {
	echo OAuthProvider::reportProblem($E);
}

?>

--TEST--
GH issue #19 - Segfault in checkOAuthRequest()
--FILE--
<?php
require 'oauth.inc';
$ret = "0";

try {
    $provider = new OAuthProvider(creationParams());
	$provider->consumerHandler(function() use (&$ret) {
		foo();
    });
	$provider->timestampNonceHandler(function() {
		bar();
    });
	$provider->tokenHandler(function() {
		global $ret;
		baz();
    });

    $provider->checkOAuthRequest("http://localhost/request_token.php", OAUTH_HTTP_METHOD_GET);

} catch (OAuthException $E) {
    echo OAuthProvider::reportProblem($E);
} catch (Throwable $T) {
	echo "Caught ", get_class($T), "\n";
}
?>
--EXPECT--
Caught Error

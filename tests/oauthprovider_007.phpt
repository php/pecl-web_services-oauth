--TEST--
OauthProvider checkOauthRequest
--FILE--
<?php
require 'oauth.inc';

try {
    $create_params = creationParams();
    $create_params['should_remove_this_param'] = 'abc';

    $provider = new OAuthProvider($create_params);
    $provider->consumerHandler(function() {
	return OAUTH_OK;
    });
    $provider->timestampNonceHandler(function() {
    	return OAUTH_OK;
    });
    $provider->tokenHandler(function() {
    	return OAUTH_OK;
    });
    $provider->setParam('should_remove_this_param', NULL);

    $provider->checkOAuthRequest("http://localhost/request_token.php", OAUTH_HTTP_METHOD_GET);

} catch (OAuthException $E) {
    echo OAuthProvider::reportProblem($E);
}

--EXPECT--
oauth_problem=signature_invalid&debug_sbs=GET&http%3A%2F%2Flocalhost%2Frequest_token.php&oauth_consumer_key%3Dapi_key%26oauth_nonce%3DraNdOM%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D12345%26oauth_token%3Da_good_token

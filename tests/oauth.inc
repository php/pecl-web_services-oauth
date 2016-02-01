<?php

function creationParams() {
	return [
		"oauth_token" => "a_good_token",
		"oauth_timestamp" => "12345",
		"oauth_nonce" => "raNdOM",
		"oauth_consumer_key" => "api_key",
		"oauth_signature" => "invalid",
		"oauth_signature_method" => OAUTH_SIG_METHOD_HMACSHA1
	];
}

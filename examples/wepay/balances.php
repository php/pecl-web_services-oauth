<?php
require './config.inc.php';

$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
try {
	$o->enableDebug();
	$access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/wepay_access_token_resp"));
	$o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);
	$resp = $o->fetch("https://wepayapi.com/v1/group/list");
	$response_info = $o->getLastResponseInfo();
	$json = $o->getLastResponse();
	$data = json_decode($json);
	foreach($data->result as $gr) {
		$resp = $o->fetch("https://wepayapi.com/v1/group/{$gr->id}");
		$group = json_decode($o->getLastResponse());
		$bal = $group->result->balance;
		$pending = $group->result->pending_balance;
		echo "\$$pending ($bal available) for {$gr->id} \"{$gr->name}\"\n";
	}
} catch(OAuthException $E) {
	echo "Exception caught!\n";
	echo "Response: ". $E->lastResponse . "\n";
}

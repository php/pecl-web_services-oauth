<?php

/* best viewed through an atom viewer, such as http://inforss.mozdev.org/ */

require("config.inc.php");

$o = new OAuth(OAUTH_CONSUMER_KEY,OAUTH_CONSUMER_SECRET,OAUTH_SIG_METHOD_HMACSHA1,OAUTH_AUTH_TYPE_AUTHORIZATION);
try {
  $access_token_info = unserialize(file_get_contents(OAUTH_TMP_DIR . "/access_token_resp"));
  $o->setToken($access_token_info["oauth_token"],$access_token_info["oauth_token_secret"]);

  $feeds_url = "http://api.netflix.com/users/". oauth_urlencode($access_token_info["user_id"]) ."/feeds";
  $o->fetch($feeds_url);

  $feeds = $o->getLastResponse();

  /* we need to pick the rental history feed (returned rentals) */

  $feeds_xml = new SimpleXMLElement($feeds);

  /* if you want to access other feeds, change the following rel attribute */
  $feed_rel = "http://schemas.netflix.com/feed.rental_history.returned";

  $returned_feed = current($feeds_xml->xpath("/resource/link[@rel=\"{$feed_rel}\"]"))->attributes();

  /* don't sign the feed requests */
  $curl = curl_init($returned_feed["href"]);
  curl_exec($curl);
} catch(OAuthException $E) {
  echo "Exception caught!\n";
  echo "Response: ". $E->lastResponse . "\n";
  var_dump($E);
}

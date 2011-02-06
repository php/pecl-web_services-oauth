<?php

/* register your own at http://twitter.com/oauth_clients */
define("TWITTER_CONSUMER_KEY","6GeLhVhmE2Oyrjrh0H81Q");
define("TWITTER_CONSUMER_SECRET","WWoyqmAsRhvjK20KU0iUzK9D0YOjLcn8JpAPTUzfY");

/* API URL's */
define("TWITTER_OAUTH_HOST","https://twitter.com");
define("TWITTER_REQUEST_TOKEN_URL",TWITTER_OAUTH_HOST."/oauth/request_token");
define("TWITTER_AUTHORIZE_URL",TWITTER_OAUTH_HOST."/oauth/authorize");
define("TWITTER_ACCESS_TOKEN_URL",TWITTER_OAUTH_HOST."/oauth/access_token");
define("TWITTER_PUBLIC_TIMELINE_API",TWITTER_OAUTH_HOST."/statuses/public_timeline.json");
define("TWITTER_UPDATE_STATUS_API",TWITTER_OAUTH_HOST."/statuses/update.json");

define("TWITTER_UPDATE_PROFILE_BG_API", "http://api.twitter.com/1/account/update_profile_background_image.json");

define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));

?>

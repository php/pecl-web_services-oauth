<?php

/* register your own at http://twitter.com/oauth_clients */
define("TWITTER_CONSUMER_KEY","6G68zzSj7VQAmYF0qWg");
define("TWITTER_CONSUMER_SECRET","TTx4jLU0wenOJ9zXZdB4RJE3Cw3y5ZJQeMYC9qQ3A");

/* API URL's */
define("TWITTER_OAUTH_HOST","https://twitter.com");
define("TWITTER_REQUEST_TOKEN_URL",TWITTER_OAUTH_HOST."/oauth/request_token");
define("TWITTER_AUTHORIZE_URL",TWITTER_OAUTH_HOST."/oauth/authorize");
define("TWITTER_ACCESS_TOKEN_URL",TWITTER_OAUTH_HOST."/oauth/access_token");
define("TWITTER_PUBLIC_TIMELINE_API",TWITTER_OAUTH_HOST."/statuses/public_timeline.json");

?>

<?php
/* you get a consumer key and secret from the OAuth provider's developer resource center */
define('OAUTH_CONSUMER_KEY','your_consumer_key');
define('OAUTH_CONSUMER_SECRET','your_consumer_secret');
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));
?>

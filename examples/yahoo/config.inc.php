<?php
/* you need to register a consumer key at developer.yahoo.com, after registering you are given the secret */
define('OAUTH_CONSUMER_KEY',"fookey");
define('OAUTH_CONSUMER_SECRET',"foosecret");
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));
?>

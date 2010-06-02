<?php
/* you need to register a consumer key at http://developer.netflix.com/member/register, after registering you are given the secret */
define('OAUTH_CONSUMER_KEY', 'pjb7agfbpmk9fvt44sz4p2na');
define('OAUTH_CONSUMER_SECRET', 'd2CUeHU53S');
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));
?>

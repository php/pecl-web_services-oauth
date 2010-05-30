<?php
/* 
   Please register your application at https://www.wepay.com/developer/register
   You can use the consumer key and secret listed here for limited testing, but it
   may be rate limited, so you are better off registering your own.
*/
define('OAUTH_CONSUMER_KEY', '388b24438fe93778e9129b164bb192');
define('OAUTH_CONSUMER_SECRET', 'd6f0a2678c');
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));

<?php
/* you need to register a consumer key at developer.yahoo.com, after registering you are given the secret */
define('OAUTH_CONSUMER_KEY',"dj0yJmk9Q0UyRDR1MEZvdDlZJmQ9WVdrOVoyWlliRmxtTm0wbWNHbzlPVGN5TmpZMU5UazMmcz1jb25zdW1lcnNlY3JldCZ4PTcy");
define('OAUTH_CONSUMER_SECRET',"26472310a35592f0fead367043f51d62249f8f19");
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));
?>

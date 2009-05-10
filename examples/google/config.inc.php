<?php
/* you need to register a consumer key at https://www.google.com/accounts/ManageDomains, after registering you are given the secret */
define('OAUTH_CONSUMER_KEY',"nil");
define('OAUTH_CONSUMER_SECRET',"nil");

/* api uri's */
define('GOOGLE_OAUTH_REQUEST_TOKEN_API', 'https://www.google.com/accounts/OAuthGetRequestToken');
define('GOOGLE_OAUTH_ACCESS_TOKEN_API', 'https://www.google.com/accounts/OAuthGetAccessToken');
define('GOOGLE_OAUTH_AUTHORIZE_API', 'https://www.google.com/accounts/OAuthAuthorizeToken');

/* full PoCo developer guide for Google is at http://code.google.com/apis/contacts/docs/poco/1.0/developers_guide.html */
define('GOOGLE_POCO_CONTACT_INFO_API', 'http://www-opensocial.googleusercontent.com/api/people/@me/@self');
define('GOOGLE_POCO_ALL_CONTACTS', 'http://www-opensocial.googleusercontent.com/api/people/@me/@all');
define('OAUTH_TMP_DIR', function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : realpath($_ENV["TMP"]));
?>

/*
  +----------------------------------------------------------------------+
  | See LICENSE file for further copyright information                   |
  +----------------------------------------------------------------------+
  | Authors: John Jawed <jawed@php.net>                                  |
  |          Felipe Pena <felipe@php.net>                                |
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_OAUTH_H
#define PHP_OAUTH_H

#ifndef Z_ADDREF_P
#define Z_ADDREF_P(pz)		(pz)->refcount++
#define Z_ADDREF_PP(ppz)	Z_ADDREF_P(*(ppz))
#endif

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 2) || PHP_MAJOR_VERSION > 5
# define OAUTH_ARGINFO
# define OAUTH_IS_CALLABLE_CC TSRMLS_CC
#else
# define OAUTH_ARGINFO static
# define OAUTH_IS_CALLABLE_CC
#endif

#define OAUTH_EXT_VER "0.99.8"
#define OAUTH_HTTP_PORT 80
#define OAUTH_HTTPS_PORT 443
#define OAUTH_MAX_REDIRS 4L
#define OAUTH_MAX_HEADER_LEN 512L
#define OAUTH_AUTH_TYPE_URI "uri"
#define OAUTH_AUTH_TYPE_FORM "form"
#define OAUTH_AUTH_TYPE_AUTHORIZATION "authorization"
#define OAUTH_AUTH_TYPE_NONE "noauth"
#define OAUTH_SIG_METHOD_HMACSHA1 "HMAC-SHA1"

#if LIBCURL_VERSION_NUM >= 0x071304
#define OAUTH_PROTOCOLS_ALLOWED CURLPROTO_HTTP | CURLPROTO_HTTPS
#endif

extern zend_module_entry oauth_module_entry;
#define phpext_oauth_ptr &oauth_module_entry

#define PHP_OAUTH_API

#define OAUTH_ATTR_CONSUMER_KEY "oauth_consumer_key"
#define OAUTH_ATTR_CONSUMER_SECRET "oauth_consumer_secret"
#define OAUTH_ATTR_ACCESS_TOKEN "oauth_access_token"
#define OAUTH_RAW_LAST_RES "oauth_last_response_raw"
#define OAUTH_ATTR_LAST_RES_INFO "oauth_last_response_info"
#define OAUTH_ATTR_SIGMETHOD "oauth_sig_method"
#define OAUTH_ATTR_TOKEN "oauth_token"
#define OAUTH_ATTR_TOKEN_SECRET "oauth_token_secret"
#define OAUTH_ATTR_AUTHMETHOD "oauth_auth_method"
#define OAUTH_ATTR_OAUTH_VERSION "oauth_version"
#define OAUTH_ATTR_OAUTH_NONCE "oauth_nonce"
#define OAUTH_ATTR_OAUTH_USER_NONCE "oauth_user_nonce"
#define OAUTH_ATTR_CA_PATH "oauth_ssl_ca_path"
#define OAUTH_ATTR_CA_INFO "oauth_ssl_ca_info"

#define OAUTH_HTTP_METHOD_GET "GET"
#define OAUTH_HTTP_METHOD_POST "POST"
#define OAUTH_HTTP_METHOD_PUT "PUT"
#define OAUTH_HTTP_METHOD_HEAD "HEAD"

#define PARAMS_FILTER_OAUTH 1
#define PARAMS_FILTER_NON_OAUTH 2
#define PARAMS_FILTER_NONE 0

#define OAUTH_FETCH_USETOKEN 1

#define OAUTH_DEFAULT_VERSION "1.0"

/* errors */
#define OAUTH_ERR_CONTENT_TYPE "invalidcontentttype"
#define OAUTH_ERR_BAD_REQUEST 400
#define OAUTH_ERR_BAD_AUTH 401
#define OAUTH_ERR_INTERNAL_ERROR 503

/* params */
#define OAUTH_PARAM_CONSUMER_KEY "oauth_consumer_key"
#define OAUTH_PARAM_SIGNATURE "oauth_signature"
#define OAUTH_PARAM_SIGNATURE_METHOD "oauth_signature_method"
#define OAUTH_PARAM_TIMESTAMP "oauth_timestamp"
#define OAUTH_PARAM_NONCE "oauth_nonce"
#define OAUTH_PARAM_VERSION "oauth_version"

#define OAUTH_PARAM_TOKEN "oauth_token"
#define OAUTH_PARAM_ASH "oauth_session_handle"
#define OAUTH_PARAM_VERIFIER "oauth_verifier"
#define OAUTH_PARAM_CALLBACK "oauth_callback"

#define OAUTH_PARAM_PREFIX "oauth_"
#define OAUTH_PARAM_PREFIX_LEN 6

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(oauth);
PHP_MSHUTDOWN_FUNCTION(oauth);
PHP_MINFO_FUNCTION(oauth);

ZEND_BEGIN_MODULE_GLOBALS(oauth);
zend_class_entry *soo_class_entry;
zend_class_entry *soo_exception_ce;
zend_object_handlers so_object_handlers;
ZEND_END_MODULE_GLOBALS(oauth);

#ifdef ZTS
#define OAUTH(v) TSRMG(oauth_globals_id, zend_oauth_globals *, v)
#else
#define OAUTH(v) (oauth_globals.v)
#endif

#ifndef zend_hash_quick_del
#define HASH_DEL_KEY_QUICK 2
#define zend_hash_quick_del(ht, arKey, nKeyLength, h) \
zend_hash_del_key_or_index(ht, arKey, nKeyLength, h, HASH_DEL_KEY_QUICK)
#endif

ZEND_EXTERN_MODULE_GLOBALS(oauth);

typedef struct {
	char		*sbs;
	smart_str	headers_in;
	smart_str	headers_out;
	smart_str	body_in;
	smart_str	body_out;
	smart_str	curl_info;
} php_so_debug;

typedef struct {
	zend_object zo;
	HashTable *properties;
	smart_str lastresponse;
	void ***thread_ctx;
	char last_location_header[OAUTH_MAX_HEADER_LEN];
	uint redirects;
	uint sslcheck; /* whether we check for SSL verification or not */
	uint debug; /* verbose output */
	uint follow_redirects; /* follow and sign redirects? */
	zval *this_ptr;
	zval *debugArr;
	php_so_debug *debug_info;
} php_so_object;

static inline zval **soo_get_property(php_so_object *soo, char *prop_name TSRMLS_DC);
static int soo_set_nonce(php_so_object *soo TSRMLS_DC);
static inline int soo_set_property(php_so_object *soo, zval *prop, char *prop_name TSRMLS_DC);
static void make_standard_query(HashTable *ht, php_so_object *soo TSRMLS_DC);
static CURLcode make_req(php_so_object *soo, const char *url, const smart_str *payload, const char *http_method, HashTable *request_headers TSRMLS_DC);

#ifndef zend_hash_quick_del
#define HASH_DEL_KEY_QUICK 2
#define zend_hash_quick_del(ht, arKey, nKeyLength, h) \
       zend_hash_del_key_or_index(ht, arKey, nKeyLength, h, HASH_DEL_KEY_QUICK)
#endif

#endif

/**
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4 noexpandtab
 */

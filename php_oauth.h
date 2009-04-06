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

#define OAUTH_EXT_VER "0.99"
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
#define OAUTH_ALLOWED_PROTOCOLS CURLPROTO_HTTP | CURLPROTO_HTTPS
#endif

extern zend_module_entry oauth_module_entry;
#define phpext_oauth_ptr &oauth_module_entry

#define PHP_OAUTH_API

#define OAUTH_ATTR_CONSUMER_KEY "oauth_consumer_key_zval"
#define OAUTH_ATTR_CONSUMER_SECRET "oauth_consumer_secret_zval"
#define OAUTH_ATTR_ACCESS_TOKEN "oauth_access_token_zval"
#define OAUTH_ATTR_LAST_RES "oauth_last_response_zval"
#define OAUTH_RAW_LAST_RES "oauth_last_response_raw"
#define OAUTH_ATTR_LAST_RES_INFO "oauth_last_response_info"
#define OAUTH_ATTR_SIGMETHOD "oauth_sig_method_zval"
#define OAUTH_ATTR_TOKEN "oauth_token_zval"
#define OAUTH_ATTR_TOKEN_SECRET "oauth_token_secret_zval"
#define OAUTH_ATTR_AUTHMETHOD "oauth_auth_method_zval"
#define OAUTH_ATTR_OAUTH_VERSION "oauth_version_zval"
#define OAUTH_ATTR_OAUTH_NONCE "oauth_nonce_zval"
#define OAUTH_ATTR_OAUTH_USER_NONCE "oauth_user_nonce_zval"

#define OAUTH_ATTR_DEBUG "oauth_debug"
#define OAUTH_ATTR_SSLCHECK "oauth_sslcheck"
#define OAUTH_ATTR_FOLLOWREDIRECTS "oauth_followredirects"

#define OAUTH_HTTP_METHOD_GET 1L
#define OAUTH_HTTP_METHOD_POST 2L
#define OAUTH_HTTP_METHOD_PUT 3L
#define OAUTH_HTTP_METHOD_HEAD 4L

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

#define OAUTH_PARAM_PREFIX "oauth_"
#define OAUTH_PARAM_PREFIX_LEN 6

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(oauth);
PHP_MSHUTDOWN_FUNCTION(oauth);
PHP_MINFO_FUNCTION(oauth);

ZEND_BEGIN_MODULE_GLOBALS(oauth)
zend_class_entry *soo_exception_ce;
ZEND_END_MODULE_GLOBALS(oauth)

#ifdef ZTS
#define OAUTH(v) TSRMG(oauth_globals_id, zend_oauth_globals *, v)
#else
#define OAUTH(v) (oauth_globals.v)
#endif

ZEND_EXTERN_MODULE_GLOBALS(oauth)

typedef struct {
	zend_object zo;
	HashTable *properties;
	zval *tmp;
	smart_str lastresponse;
	void ***thread_ctx;
	char last_location_header[OAUTH_MAX_HEADER_LEN];
} php_so_object;

static inline zval **soo_get_property(php_so_object *soo, char *prop_name TSRMLS_DC);
static int soo_set_nonce(php_so_object *soo TSRMLS_DC);
static inline int soo_set_property(php_so_object *soo, zval *prop, char *prop_name TSRMLS_DC);

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

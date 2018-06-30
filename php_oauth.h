/*
  +----------------------------------------------------------------------+
  | See LICENSE file for further copyright information                   |
  +----------------------------------------------------------------------+
  | Authors: John Jawed <jawed@php.net>                                  |
  |          Felipe Pena <felipe@php.net>                                |
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_OAUTH_H
#define PHP_OAUTH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#ifdef PHP_WIN32
#include "win32/time.h"
#endif

#include "SAPI.h"
#include "zend_API.h"
#include "zend_variables.h"
#include "ext/standard/head.h"
#include "php_globals.h"
#include "php_main.h"
#include "php_ini.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_rand.h"
#include "ext/standard/php_smart_string.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_versioning.h"
#include "ext/standard/url.h"
#include "php_variables.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "php_globals.h"
#include "ext/standard/file.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_lcg.h"
#include "ext/pcre/php_pcre.h"
#include "php_network.h"

#if OAUTH_USE_CURL
#include <curl/curl.h>
#define CLEANUP_CURL_AND_FORM(f,h)	 \
	curl_easy_cleanup(h);	 \
	curl_formfree(f);
#endif

#define PHP_OAUTH_VERSION 2.0.3-dev

#define __stringify_1(x)    #x
#define __stringify(x)      __stringify_1(x)
#define __OAUTH_EXT_VER PHP_OAUTH_VERSION
#define OAUTH_EXT_VER __stringify(__OAUTH_EXT_VER)
#define OAUTH_USER_AGENT "PECL-OAuth/" __stringify(__OAUTH_EXT_VER)
#define OAUTH_HTTP_PORT 80
#define OAUTH_HTTPS_PORT 443
#define OAUTH_MAX_REDIRS 4L
#define OAUTH_MAX_HEADER_LEN 512L
#define OAUTH_AUTH_TYPE_URI 0x01
#define OAUTH_AUTH_TYPE_FORM 0x02
#define OAUTH_AUTH_TYPE_AUTHORIZATION 0x03
#define OAUTH_AUTH_TYPE_NONE 0x04

#define OAUTH_SIG_METHOD_HMACSHA1 "HMAC-SHA1"
#define OAUTH_SIG_METHOD_HMACSHA256 "HMAC-SHA256"
#define OAUTH_SIG_METHOD_RSASHA1 "RSA-SHA1"
#define OAUTH_SIG_METHOD_PLAINTEXT "PLAINTEXT"

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
#define OAUTH_HTTP_METHOD_DELETE "DELETE"

#define OAUTH_REQENGINE_STREAMS 1
#define OAUTH_REQENGINE_CURL 2

#define OAUTH_FETCH_USETOKEN 1
#define OAUTH_FETCH_SIGONLY 2
#define OAUTH_FETCH_HEADONLY 4
#define OAUTH_OVERRIDE_HTTP_METHOD 8

#define OAUTH_SSLCHECK_NONE 0
#define OAUTH_SSLCHECK_HOST 1
#define OAUTH_SSLCHECK_PEER 2
#define OAUTH_SSLCHECK_BOTH (OAUTH_SSLCHECK_HOST | OAUTH_SSLCHECK_PEER)

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

/* values */
#define OAUTH_CALLBACK_OOB "oob"

#define OAUTH_PARAM_PREFIX "oauth_"
#define OAUTH_PARAM_PREFIX_LEN 6

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(oauth);
PHP_MSHUTDOWN_FUNCTION(oauth);
PHP_MINFO_FUNCTION(oauth);

#ifdef ZTS
#define OAUTH(v) TSRMG(oauth_globals_id, zend_oauth_globals *, v)
#else
#define OAUTH(v) (oauth_globals.v)
#endif

typedef enum { OAUTH_SIGCTX_TYPE_NONE, OAUTH_SIGCTX_TYPE_HMAC, OAUTH_SIGCTX_TYPE_RSA, OAUTH_SIGCTX_TYPE_PLAIN } oauth_sigctx_type;

typedef struct {
	oauth_sigctx_type	type;
	char				*hash_algo;
	zval				privatekey;
} oauth_sig_context;

#define OAUTH_SIGCTX_INIT(ctx) { \
		(ctx) = emalloc(sizeof(*(ctx))); \
		(ctx)->type = OAUTH_SIGCTX_TYPE_NONE; \
		(ctx)->hash_algo = NULL; \
		ZVAL_UNDEF(&ctx->privatekey); \
	}

#define OAUTH_SIGCTX_HMAC(ctx, algo) { \
		(ctx)->type = OAUTH_SIGCTX_TYPE_HMAC; \
		(ctx)->hash_algo = algo; \
	}

#define OAUTH_SIGCTX_PLAIN(ctx) { \
		(ctx)->type = OAUTH_SIGCTX_TYPE_PLAIN; \
	}

#define OAUTH_SIGCTX_FREE_PRIVATEKEY(ctx) { \
		if (Z_TYPE(ctx->privatekey) != IS_UNDEF) { \
			oauth_free_privatekey(&ctx->privatekey); \
			ZVAL_UNDEF(&ctx->privatekey); \
		} \
	}

#define OAUTH_SIGCTX_SET_PRIVATEKEY(ctx, privkey) { \
		OAUTH_SIGCTX_FREE_PRIVATEKEY(ctx) \
		ZVAL_DUP(&ctx->privatekey, &privkey); \
	}

#define OAUTH_SIGCTX_RSA(ctx, algo) { \
		(ctx)->type = OAUTH_SIGCTX_TYPE_RSA; \
		(ctx)->hash_algo = algo; \
	}

#define OAUTH_SIGCTX_FREE(ctx) { \
		if (ctx) { \
			OAUTH_SIGCTX_FREE_PRIVATEKEY(ctx) \
			efree((ctx)); \
		} \
	}

typedef struct {
	zend_string		*sbs;
	smart_string	headers_in;
	smart_string	headers_out;
	smart_string	body_in;
	smart_string	body_out;
	smart_string	curl_info;
} php_so_debug;

typedef struct {
	HashTable *properties;
	smart_string lastresponse;
	smart_string headers_in;
	smart_string headers_out;
	char last_location_header[OAUTH_MAX_HEADER_LEN];
	uint redirects;
	uint multipart_files_num;
	uint sslcheck; /* whether we check for SSL verification or not */
	uint debug; /* verbose output */
	uint follow_redirects; /* follow and sign redirects? */
	uint reqengine; /* streams or curl */
	long timeout; /* timeout in milliseconds */
	char *nonce;
	char *timestamp;
	zend_string *signature;
	zval *this_ptr;
	zval debugArr;
	oauth_sig_context *sig_ctx;
	php_so_debug *debug_info;
	char **multipart_files;
	char **multipart_params;
	uint is_multipart;
	void ***thread_ctx;
	zend_object zo;
} php_so_object;

static inline php_so_object *so_object_from_obj(zend_object *obj) /* {{{ */ {
    return (php_so_object*)((char*)(obj) - XtOffsetOf(php_so_object, zo));
}
/* }}} */

static inline php_so_object *Z_SOO_P(zval *zv) /* {{{ */ {
	php_so_object *soo = so_object_from_obj(Z_OBJ_P((zv)));
	soo->this_ptr = zv;
	return soo;
}
/* }}} */

#ifndef zend_parse_parameters_none
#define zend_parse_parameters_none()    \
	zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "")
#endif

void soo_handle_error(php_so_object *soo, long errorCode, char *msg, char *response, char *additional_info TSRMLS_DC);
zend_string *oauth_generate_sig_base(php_so_object *soo, const char *http_method, const char *uri, HashTable *post_args, HashTable *extra_args TSRMLS_DC);

#ifndef zend_hash_quick_del
#define HASH_DEL_KEY_QUICK 2
#define zend_hash_quick_del(ht, arKey, nKeyLength, h) \
       zend_hash_del_key_or_index(ht, arKey, nKeyLength, h, HASH_DEL_KEY_QUICK)
#endif

#define SO_ME(func, arg_info, flags) PHP_ME(oauth, func, arg_info, flags)
#define SO_MALIAS(func, alias, arg_info, flags) PHP_MALIAS(oauth, func, alias, arg_info, flags)
#define SO_METHOD(func) PHP_METHOD(oauth, func)
#define FREE_ARGS_HASH(a)	\
	if (a) { \
		zend_hash_destroy(a);	\
		FREE_HASHTABLE(a); \
	}

#define INIT_smart_string(a) \
	(a).len = 0; \
	(a).c = NULL;

#define HTTP_IS_REDIRECT(http_response_code) \
	(http_response_code > 300 && http_response_code < 304)

#define INIT_DEBUG_INFO(a) \
	INIT_smart_string((a)->headers_out); \
	INIT_smart_string((a)->body_in); \
	INIT_smart_string((a)->body_out); \
	INIT_smart_string((a)->curl_info);

#define FREE_DEBUG_INFO(a) \
	smart_string_free(&(a)->headers_out); \
	smart_string_free(&(a)->body_in); \
	smart_string_free(&(a)->body_out); \
	smart_string_free(&(a)->curl_info);

/* this and code that uses it is from ext/curl/interface.c */
#define CAAL(s, v) add_assoc_long_ex(&info, s, sizeof(s) - 1, (long) v);
#define CAAD(s, v) add_assoc_double_ex(&info, s, sizeof(s) - 1, (double) v);
#define CAAS(s, v) add_assoc_string_ex(&info, s, sizeof(s) - 1, (char *) (v ? v : ""));

#define ADD_DEBUG_INFO(a, k, s, t) \
	if(s.len) { \
		smart_string_0(&(s)); \
		if(t) { \
			zend_string *tmp, *s_zstr = zend_string_init((s).c, (s).len, 0); \
			tmp = php_trim(s_zstr, NULL, 0, 3); \
			add_assoc_string((a), k, ZSTR_VAL(tmp)); \
			zend_string_release(tmp); \
			zend_string_release(s_zstr); \
		} else { \
			add_assoc_string((a), k, (s).c); \
		} \
	}

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define OAUTH_OK SUCCESS

#if OAUTH_USE_CURL
long make_req_curl(php_so_object *soo, const char *url, const smart_string *payload, const char *http_method, HashTable *request_headers TSRMLS_DC);
#if LIBCURL_VERSION_NUM >= 0x071304
#define OAUTH_PROTOCOLS_ALLOWED CURLPROTO_HTTP | CURLPROTO_HTTPS
#endif
#endif


void oauth_free_privatekey(zval *privatekey TSRMLS_DC);
zend_string *soo_sign(php_so_object *soo, char *message, zval *cs, zval *ts, const oauth_sig_context *ctx TSRMLS_DC);
oauth_sig_context *oauth_create_sig_context(const char *sigmethod);
zend_string *oauth_url_encode(char *url, int url_len);


// Compatibility macros
#if PHP_VERSION_ID < 70300
#define OAUTH_URL_STR(a) (a)
#define OAUTH_URL_LEN(a) strlen(a)
#else
#define OAUTH_URL_STR(a) ZSTR_VAL(a)
#define OAUTH_URL_LEN(a) ZSTR_LEN(a)
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

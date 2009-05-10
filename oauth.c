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
#include "ext/standard/php_smart_str.h"
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

#include <curl/curl.h>

#include "php_oauth.h"

#define SO_ME(func, arg_info, flags) PHP_ME(oauth, func, arg_info, flags)
#define SO_MALIAS(func, alias, arg_info, flags) PHP_MALIAS(oauth, func, alias, arg_info, flags)
#define SO_METHOD(func) PHP_METHOD(oauth, func)
#define CLEANUP_CURL_AND_FORM(f,h)	\
	curl_easy_cleanup(h);			\
	curl_formfree(f);
#define FREE_ARGS_HASH(a)	\
	if (a) { \
		zend_hash_destroy(a);	\
		FREE_HASHTABLE(a); \
	}

#define INIT_SMART_STR(a) \
	(a).len = 0; \
	(a).c = NULL;

#define HTTP_IS_REDIRECT(http_response_code) \
	(http_response_code > 300 && http_response_code < 304)

#define INIT_DEBUG_INFO(a) \
	INIT_SMART_STR((a)->headers_in); \
	INIT_SMART_STR((a)->headers_out); \
	INIT_SMART_STR((a)->body_in); \
	INIT_SMART_STR((a)->body_out); \
	INIT_SMART_STR((a)->curl_info);

#define FREE_DEBUG_INFO(a) \
	smart_str_free(&(a)->headers_in); \
	smart_str_free(&(a)->headers_out); \
	smart_str_free(&(a)->body_in); \
	smart_str_free(&(a)->body_out); \
	smart_str_free(&(a)->curl_info); 

/* this and code that uses it is from ext/curl/interface.c */
#define CAAL(s, v) add_assoc_long_ex(info, s, sizeof(s), (long) v);
#define CAAD(s, v) add_assoc_double_ex(info, s, sizeof(s), (double) v);
#define CAAS(s, v) add_assoc_string_ex(info, s, sizeof(s), (char *) (v ? v : ""), 1);

#define ADD_DEBUG_INFO(a, k, s, t) \
	if(s.len) { \
		smart_str_0(&(s)); \
		if(t) { \
			tmp = php_trim((s).c, (s).len, NULL, 0, NULL, 3 TSRMLS_CC); \
			add_assoc_string((a), k, tmp, 1); \
			efree(tmp); \
		} else { \
			add_assoc_string((a), k, (s).c, 1); \
		} \
	}

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static zend_class_entry *soo_class_entry;
static zend_class_entry *soo_exception_ce;
static zend_object_handlers so_object_handlers;

static int oauth_parse_str(char *params, zval *dest_array TSRMLS_DC) /* {{{ */
{
	char *res = NULL, *var, *val, *separator = NULL;
	char *strtok_buf = NULL;

	if (!params) {
		return FAILURE;
	}

	res = params;
	separator = (char *) estrdup(PG(arg_separator).input);
	var = php_strtok_r(res, separator, &strtok_buf);
	while (var) {
		val = strchr(var, '=');

		if (val) { /* have a value */
			int val_len;

			*val++ = '\0';
			php_url_decode(var, strlen(var));
			val_len = php_url_decode(val, strlen(val));
			val = estrndup(val, val_len);
		} else {
			int val_len;

			php_url_decode(var, strlen(var));
			val_len = 0;
			val = estrndup("", val_len);
		}
		add_assoc_string(dest_array, var, val, 1);
		efree(val);
		var = php_strtok_r(NULL, separator, &strtok_buf);
	}

	efree(separator);
	return SUCCESS;
}
/* }}} */

static inline php_so_object *fetch_so_object(zval *obj TSRMLS_DC) /* {{{ */
{
	php_so_object *soo = (php_so_object *)zend_object_store_get_object(obj TSRMLS_CC);

	soo->this_ptr = obj;

	return soo;
}
/* }}} */

static int so_set_response_args(HashTable *hasht, zval *data, zval *retarray TSRMLS_DC) /* {{{ */
{
	if (data && Z_TYPE_P(data) == IS_STRING) {
		ulong h = zend_hash_func(OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES));

#if jawed_0
		/* don't need this till we fully implement error reporting ... */
		if (!onlyraw) {
			zend_hash_quick_update(hasht, OAUTH_ATTR_LAST_RES, sizeof(OAUTH_ATTR_LAST_RES), h, &arrayArg, sizeof(zval *), NULL);
		} else {
			zend_hash_quick_update(hasht, OAUTH_ATTR_LAST_RES, sizeof(OAUTH_ATTR_LAST_RES), h, &rawval, sizeof(zval *), NULL);

			h = zend_hash_func(OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES));
			zend_hash_quick_update(hasht, OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES), h, &rawval, sizeof(zval *), NULL);
		}
		return data;
#endif
		if (retarray) {
			char *res = NULL;

			res = estrndup(Z_STRVAL_P(data), Z_STRLEN_P(data));
			/* do not use oauth_parse_str here, we want the result to pass through input filters */
			sapi_module.treat_data(PARSE_STRING, res, retarray TSRMLS_CC);
		}

		return zend_hash_quick_update(hasht, OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES), h, &data, sizeof(zval *), NULL);
	}
	return FAILURE;
}
/* }}} */

static zval *so_set_response_info(HashTable *hasht, zval *info) /* {{{ */
{
	ulong h = zend_hash_func(OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO));

	if (zend_hash_quick_update(hasht, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO), h, &info, sizeof(zval *), NULL) != SUCCESS) {
		return NULL;
	}
	return info;
}
/* }}} */

static void so_object_free_storage(void *obj TSRMLS_DC) /* {{{ */
{
	php_so_object *soo;

	soo = (php_so_object *) obj;
	zend_object_std_dtor(&soo->zo TSRMLS_CC);

	if (soo->lastresponse.c) {
		smart_str_free(&soo->lastresponse);
	}
	efree(obj);
}
/* }}} */

static zend_object_value php_so_register_object(php_so_object *soo TSRMLS_DC) /* {{{ */
{
	zend_object_value rv;

	rv.handle = zend_objects_store_put(soo, (zend_objects_store_dtor_t)zend_objects_destroy_object, so_object_free_storage, NULL TSRMLS_CC);
	rv.handlers = (zend_object_handlers *) &so_object_handlers;
	return rv;
}
/* }}} */

static php_so_object* php_so_object_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	php_so_object *nos;

	nos = ecalloc(1, sizeof(php_so_object));

	zend_object_std_init(&nos->zo, ce TSRMLS_CC);

	nos->zo.ce = ce;
	nos->zo.guards = NULL;
	return nos;
}
/* }}} */

static zend_object_value new_so_object(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	php_so_object *soo;

	soo = php_so_object_new(ce TSRMLS_CC);
	return php_so_register_object(soo TSRMLS_CC);
}
/* }}} */

void soo_handle_error(long errorCode, char *msg, char *response TSRMLS_DC) /* {{{ */
{
	zval *ex;
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 2)
	zend_class_entry *dex = zend_exception_get_default(), *soox = soo_exception_ce;
#else
	zend_class_entry *dex = zend_exception_get_default(TSRMLS_C), *soox = soo_exception_ce;
#endif

	MAKE_STD_ZVAL(ex);
	object_init_ex(ex,soox);

	if (!errorCode) {
		php_error(E_WARNING, "caller did not pass an errorcode!");
	} else {
		zend_update_property_long(dex, ex, "code", sizeof("code")-1, errorCode TSRMLS_CC);
	}
	if (response) {
		zend_update_property_string(dex, ex, "lastResponse", sizeof("lastResponse")-1, response TSRMLS_CC);
	}

	zend_update_property_string(dex, ex, "message", sizeof("message")-1, msg TSRMLS_CC);
	zend_throw_exception_object(ex TSRMLS_CC);
}
/* }}} */

static void oauth_prop_hash_dtor(php_so_object *soo TSRMLS_DC) /* {{{ */
{
	HashTable *ht;

	ht = soo->properties;

	FREE_ARGS_HASH(ht);
}
/* }}} */

static char *soo_hmac_sha1(char *message, zval *cs, zval *ts TSRMLS_DC) /* {{{ */
{
	zval *args[4],*retval,*func;
	char *tret;
	int ret,retlen;
	unsigned char *result;

	MAKE_STD_ZVAL(func);
	ZVAL_STRING(func, "hash_hmac", 0);

	if (!zend_is_callable(func, 0, NULL OAUTH_IS_CALLABLE_CC)) {
		FREE_ZVAL(func);
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "HMAC signature generation failed, is ext/hash installed?", NULL TSRMLS_CC);
		return NULL;
	}

	if (ts) {
		spprintf(&tret, 0, "%s&%s", Z_STRVAL_P(cs), Z_STRVAL_P(ts));
	} else {
		spprintf(&tret, 0, "%s&", Z_STRVAL_P(cs));
	}

	MAKE_STD_ZVAL(retval);
	MAKE_STD_ZVAL(args[0]);
	MAKE_STD_ZVAL(args[1]);
	MAKE_STD_ZVAL(args[2]);
	MAKE_STD_ZVAL(args[3]);

	ZVAL_STRING(args[0], "sha1", 0);
	ZVAL_STRING(args[1], message, 0);
	ZVAL_STRING(args[2], tret, 0);
	ZVAL_BOOL(args[3], 1);

	ret = call_user_function(EG(function_table), NULL, func, retval, 4, args TSRMLS_CC);
	result = php_base64_encode((unsigned char *)Z_STRVAL_P(retval), Z_STRLEN_P(retval), &retlen);

	efree(tret);
	zval_ptr_dtor(&retval);
	FREE_ZVAL(func);
	FREE_ZVAL(args[0]);
	FREE_ZVAL(args[1]);
	FREE_ZVAL(args[2]);
	FREE_ZVAL(args[3]);

	return (char *)result;
}
/* }}} */

static int soo_set_nonce(php_so_object *soo TSRMLS_DC) /* {{{ */
{
	zval *data_ptr, *zonc;
	char *uniqid;
	int sec, usec;
	struct timeval tv;
	ulong h = zend_hash_func(OAUTH_ATTR_OAUTH_NONCE, sizeof(OAUTH_ATTR_OAUTH_NONCE));

	if (zend_hash_quick_find(soo->properties, OAUTH_ATTR_OAUTH_USER_NONCE, sizeof(OAUTH_ATTR_OAUTH_NONCE), h, (void *)&data_ptr) == SUCCESS) {
		Z_ADDREF_P(data_ptr);
		return soo_set_property(soo, data_ptr, OAUTH_ATTR_OAUTH_NONCE TSRMLS_CC);
	}

	/* XXX maybe find a better way to generate a nonce... */
	gettimeofday((struct timeval *) &tv, (struct timezone *) NULL);
	sec = (int) tv.tv_sec;
	usec = (int) (tv.tv_usec % 0x100000);

	spprintf(&uniqid, 0, "%ld%08x%05x%.8f", php_rand(TSRMLS_C), sec, usec, php_combined_lcg(TSRMLS_C) * 10);

	MAKE_STD_ZVAL(zonc);
	ZVAL_STRING(zonc, uniqid, 1);
	efree(uniqid);

	return soo_set_property(soo, zonc, OAUTH_ATTR_OAUTH_NONCE TSRMLS_CC);
}
/* }}} */

static inline zval **soo_get_property(php_so_object *soo, char *prop_name TSRMLS_DC) /* {{{ */
{
	size_t prop_len = 0;
	void *data_ptr;
	ulong h;

	if (!strcmp(prop_name, OAUTH_ATTR_OAUTH_NONCE) && soo_set_nonce(soo TSRMLS_CC) == FAILURE) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Failed generating nonce", NULL TSRMLS_CC);
		return NULL;
	}
	prop_len = strlen(prop_name);
	h = zend_hash_func(prop_name, prop_len+1);

	if (zend_hash_quick_find(soo->properties, prop_name, prop_len+1, h, (void **)&data_ptr) == SUCCESS) {
		return (zval **)data_ptr;
	}
	return NULL;
}
/* }}} */

/* XXX for auth type, need to make sure that the auth type is actually supported before setting */
static inline int soo_set_property(php_so_object *soo, zval *prop, char *prop_name TSRMLS_DC) /* {{{ */
{
	size_t prop_len = 0;
	ulong h;

	prop_len = strlen(prop_name);
	h = zend_hash_func(prop_name, prop_len+1);

	return zend_hash_quick_update(soo->properties, prop_name, prop_len+1, h, (void *)&prop, sizeof(zval *), NULL);
}
/* }}} */

static char *oauth_url_encode(char *url) /* {{{ */
{
	char *urlencoded = NULL, *ret;
	int out_len, ret_len;

	if(url) {
		urlencoded = php_raw_url_encode(url, strlen(url), &out_len);
	}

	if (urlencoded) {
		ret = php_str_to_str_ex(urlencoded, out_len, "%7E", sizeof("%7E")-1, "~", sizeof("~")-1, &ret_len, 0, NULL);
		efree(urlencoded);
		return ret;
	}
	return NULL;
}
/* }}} */

/* build url-encoded string from args, optionally starting with & and optionally filter oauth params or non-oauth params */ 
int oauth_http_build_query(smart_str *s, HashTable *args, zend_bool prepend_amp, int filter)
{
	void *cur_val;
	char *arg_key = NULL, *cur_key = NULL, *param_value;
	uint cur_key_len;
	int numargs = 0;
	int is_oauth_param = 0;

	if (args) {
		for (zend_hash_internal_pointer_reset(args);
				zend_hash_get_current_key_ex(args, &cur_key, &cur_key_len, NULL, 0, NULL) != HASH_KEY_NON_EXISTANT;
				zend_hash_move_forward(args)) {
			is_oauth_param = !strncmp(OAUTH_PARAM_PREFIX, cur_key, OAUTH_PARAM_PREFIX_LEN);
			/* apply filter where applicable */
			if (filter==PARAMS_FILTER_NONE 
					|| (filter==PARAMS_FILTER_OAUTH && !is_oauth_param) 
					|| (filter==PARAMS_FILTER_NON_OAUTH && is_oauth_param)) {
				if (prepend_amp) {
					smart_str_appendc(s, '&');
				}
				zend_hash_get_current_data(args, (void **)&cur_val);
				arg_key = oauth_url_encode(cur_key);
				param_value = oauth_url_encode(Z_STRVAL_PP((zval **)cur_val));

				if(arg_key) {
					smart_str_appends(s, arg_key);
					efree(arg_key);
				}
				smart_str_appendc(s, '=');
				if (param_value) {
					smart_str_appends(s, param_value);
					efree(param_value);
				}
				prepend_amp = TRUE;
				++numargs;
			}
		}
	}
	return numargs;
}

/* retrieves parameter value from the _GET or _POST superglobal */
void get_request_param(char *arg_name, char **return_val, int *return_len TSRMLS_DC)
{
	zval **ptr;
	if (
	    (PG(http_globals)[TRACK_VARS_GET] && SUCCESS==zend_hash_find(HASH_OF(PG(http_globals)[TRACK_VARS_GET]), arg_name, strlen(arg_name)+1, (void**)&ptr) && IS_STRING==Z_TYPE_PP(ptr)) || 
	    (PG(http_globals)[TRACK_VARS_POST] && SUCCESS==zend_hash_find(HASH_OF(PG(http_globals)[TRACK_VARS_POST]), arg_name, strlen(arg_name)+1, (void**)&ptr) && IS_STRING==Z_TYPE_PP(ptr))
	   ) {
		*return_val = Z_STRVAL_PP(ptr);
		*return_len = Z_STRLEN_PP(ptr);
		return;
	}
	*return_val = NULL;
	*return_len = 0;
}

/*
 * This function does not currently care to respect parameter precedence, in the sense that if a common param is defined
 * in POST/GET or Authorization header, the precendence is defined by: OAuth Core 1.0 section 9.1.1
 */

static char *oauth_generate_sig_base(php_so_object *soo, const char *http_method, const char *uri, HashTable *post_args, HashTable *extra_args TSRMLS_DC) /* {{{ */
{
	zval *func, *exret2, *exargs2[2];
	ulong oauth_sig_h;
	zend_bool prepend_amp = FALSE;
	char *query;
	char *s_port = NULL, *bufz = NULL, *sbs_query_part = NULL, *sbs_scheme_part = NULL;
	HashTable *decoded_args;
	php_url *urlparts;
	smart_str sbuf = {0}, squery = {0};
	int numargs = 0;

	urlparts = php_url_parse_ex(uri, strlen(uri));

	if (urlparts) {
		if (!urlparts->host && !urlparts->scheme) {
			soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid url when trying to build base signature string", NULL TSRMLS_CC);
			php_url_free(urlparts);
			return NULL;
		}
		smart_str_appends(&sbuf, urlparts->scheme);
		smart_str_appends(&sbuf, "://");
		smart_str_appends(&sbuf, urlparts->host);

		if (urlparts->port && ((!strcmp("http", urlparts->scheme) && OAUTH_HTTP_PORT != urlparts->port)
					|| (!strcmp("https", urlparts->scheme) && OAUTH_HTTPS_PORT != urlparts->port))) {
			spprintf(&s_port, 0, "%d", urlparts->port);
			smart_str_appendc(&sbuf, ':');
			smart_str_appends(&sbuf, s_port);
			efree(s_port);
		}

		if (urlparts->path) {
			smart_str_appends(&sbuf, urlparts->path);
			smart_str_0(&sbuf);

			numargs += oauth_http_build_query(&squery, post_args, FALSE, PARAMS_FILTER_NONE);

			numargs += oauth_http_build_query(&squery, extra_args, numargs ? TRUE : FALSE, PARAMS_FILTER_NONE);

			if (urlparts->query) {
				smart_str_appendc(&squery, '&');
				smart_str_appends(&squery, urlparts->query);
			}

			MAKE_STD_ZVAL(func);
			MAKE_STD_ZVAL(exret2);
			MAKE_STD_ZVAL(exargs2[0]);
			array_init(exargs2[0]);

			smart_str_0(&squery);
			query = estrdup(squery.c);

			oauth_parse_str(query, exargs2[0] TSRMLS_CC);

			efree(query);
			smart_str_free(&squery);

			/* remove oauth_signature if it's in the hash */
			oauth_sig_h = zend_hash_func(OAUTH_PARAM_SIGNATURE, sizeof(OAUTH_PARAM_SIGNATURE));
			zend_hash_quick_del(Z_ARRVAL_P(exargs2[0]), OAUTH_PARAM_SIGNATURE, sizeof(OAUTH_PARAM_SIGNATURE), oauth_sig_h);

			MAKE_STD_ZVAL(exargs2[1]);
			ZVAL_STRING(exargs2[1], "strnatcmp", 0);
			ZVAL_STRING(func, "uksort", 0);

			/* now the extra args */
			call_user_function(EG(function_table), NULL, func, exret2, 2, exargs2 TSRMLS_CC);
			zval_ptr_dtor(&exret2);

			if (Z_TYPE_P(exargs2[0]) == IS_ARRAY) {
				/* time to re-invent the query */
				if (Z_ARRVAL_P(exargs2[0])) {
					decoded_args = Z_ARRVAL_P(exargs2[0]);
					prepend_amp = FALSE;

					/* this one should check if values are non empty */
					oauth_http_build_query(&squery, decoded_args, FALSE, PARAMS_FILTER_NONE);
					smart_str_0(&squery);
				} else {
					soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Was not able to get oauth parameters!", NULL TSRMLS_CC);
				}
			}
			FREE_ZVAL(func);
			zval_ptr_dtor(&exargs2[0]);
			FREE_ZVAL(exargs2[1]);

			sbs_query_part = oauth_url_encode(squery.c);
			sbs_scheme_part = oauth_url_encode(sbuf.c);

			spprintf(&bufz, 0, "%s&%s&%s", http_method, sbs_scheme_part, sbs_query_part);
			/* TODO move this into oauth_get_http_method()
			   soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL TSRMLS_CC);
			   */
			if(sbs_query_part) {
				efree(sbs_query_part);
			}
			if(sbs_scheme_part) {
				efree(sbs_scheme_part);
			}
			smart_str_free(&sbuf);
			smart_str_free(&squery);
		}

		php_url_free(urlparts);

		if(soo && soo->debug) {
			if(soo->debug_info->sbs) {
				efree(soo->debug_info->sbs);
			}
			soo->debug_info->sbs = estrdup(bufz);
		}
		return bufz;
	}
	return NULL;
}
/* }}} */

static size_t soo_read_response(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	uint relsize;
	php_so_object *soo = (php_so_object *)ctx;

	relsize = size * nmemb;
	smart_str_appendl(&soo->lastresponse, ptr, relsize);

	return relsize;
}

int oauth_debug_handler(CURL *ch, curl_infotype type, char *data, size_t data_len, void *ctx) /* {{{ */
{
	php_so_debug *sdbg;
	char *z_data = NULL;
	smart_str *dest;

	if(data_len > 1 && data[0]=='\r' && data[1]=='\n') { /* ignore \r\n */
		return 0;
	}

	sdbg = (php_so_debug *)ctx;
	z_data = emalloc(data_len + 2);
	memset(z_data, 0, data_len + 2);
	memcpy(z_data, data, data_len);
	z_data[data_len] = '\0';

	switch(type) {
		case CURLINFO_TEXT:
			dest = &sdbg->curl_info;
			break;
		case CURLINFO_HEADER_IN:
			dest = &sdbg->headers_in;
			break;
		case CURLINFO_HEADER_OUT:
			dest = &sdbg->headers_out;
			break;
		case CURLINFO_DATA_IN:
			dest = &sdbg->body_in;
			break;
		case CURLINFO_DATA_OUT:
			dest = &sdbg->body_out;
			break;
		default:
			dest = NULL;
	}

	if(dest) {
		smart_str_appends(dest, z_data);
	}
	efree(z_data);

	return 0;
}
/* }}} */

static size_t soo_read_header(void *ptr, size_t size, size_t nmemb, void *ctx)
{
	char *header;
	size_t hlen;
	php_so_object *soo;
	unsigned int xhead_clen = 0;
	unsigned int location_len = 8;

	header = (char *)ptr;
	hlen = nmemb * size;
	soo = (php_so_object *)ctx;

	if(header[hlen]!='\0')
	{
		header[hlen] = '\0';
	}

	/* handle Location header */
	if(hlen > location_len && !strncasecmp(header,"Location",location_len)) {
		header += location_len + 1 /*:*/;
		xhead_clen += location_len;
		while(*header==' ' && xhead_clen<(OAUTH_MAX_HEADER_LEN))
		{
			header++;
			++xhead_clen;
		}
		strncpy(soo->last_location_header,header,hlen - xhead_clen - 3 /*\r\n\0*/);
	}
	return hlen;
}

static void oauth_set_debug_info(php_so_object *soo TSRMLS_DC) {
	zval *debugInfo;
	char *tmp;

	if(soo->debug_info) {

		debugInfo = soo->debugArr;
		
		if(!debugInfo) {
			ALLOC_INIT_ZVAL(debugInfo);
			array_init(debugInfo);
		} else {
			FREE_ARGS_HASH(HASH_OF(debugInfo));
			array_init(debugInfo);
		}

		if(soo->debug_info->sbs) {
			add_assoc_string(debugInfo, "sbs", soo->debug_info->sbs, 1);
		}

		ADD_DEBUG_INFO(debugInfo, "headers_sent", soo->debug_info->headers_out, 1);
		ADD_DEBUG_INFO(debugInfo, "headers_recv", soo->debug_info->headers_in, 1);
		ADD_DEBUG_INFO(debugInfo, "body_sent", soo->debug_info->body_out, 0);
		ADD_DEBUG_INFO(debugInfo, "body_recv", soo->debug_info->body_in, 0);
		ADD_DEBUG_INFO(debugInfo, "info", soo->debug_info->curl_info, 0);

		zend_update_property(soo_class_entry, soo->this_ptr, "debugInfo", sizeof("debugInfo") - 1, debugInfo TSRMLS_CC);

		soo->debugArr = debugInfo;
	} 
}

static int add_arg_for_req(HashTable *ht, const char *arg, const char *val TSRMLS_DC) /* {{{ */
{
	zval *varg;
	ulong h;

	if (!val) {
		char *sarg;
		spprintf(&sarg, 0, "Error adding parameter to request ('%s')", arg);
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, sarg, NULL TSRMLS_CC);
		efree(sarg);
		return FAILURE;
	}
	MAKE_STD_ZVAL(varg);
	ZVAL_STRING(varg, (char *)val, 1);

	h = zend_hash_func((char *)arg, strlen(arg)+1);
	zend_hash_quick_update(ht, (char *)arg, strlen(arg)+1, h, &varg, sizeof(zval *), NULL);

	return SUCCESS;
}
/* }}} */

void oauth_add_signature_header(HashTable *request_headers, HashTable *oauth_args TSRMLS_DC)
{
	smart_str sheader = {0};
	zend_bool prepend_comma = FALSE;

	zval **curval;
	char *param_name, *param_val, *cur_key;
	uint cur_key_len;
	ulong num_key;

	smart_str_appends(&sheader, "OAuth ");

	for (zend_hash_internal_pointer_reset(oauth_args);
			zend_hash_get_current_data(oauth_args, (void *)&curval) == SUCCESS;
			zend_hash_move_forward(oauth_args)) {
		zend_hash_get_current_key_ex(oauth_args, &cur_key, &cur_key_len, &num_key, 0, NULL);

		if (prepend_comma) {
			smart_str_appendc(&sheader, ',');
		}
		param_name = oauth_url_encode(cur_key);
		param_val = oauth_url_encode(Z_STRVAL_PP(curval));

		smart_str_appends(&sheader, param_name);
		smart_str_appendc(&sheader, '=');
		smart_str_appends(&sheader, "\"");
		smart_str_appends(&sheader, param_val);
		smart_str_appends(&sheader, "\"");

		efree(param_name);
		efree(param_val);
		prepend_comma = TRUE;
	}
	smart_str_0(&sheader);
	add_arg_for_req(request_headers, "Authorization", sheader.c TSRMLS_CC);

	smart_str_free(&sheader);
}

static CURLcode make_req(php_so_object *soo, const char *url, const smart_str *payload, const char *http_method, HashTable *request_headers TSRMLS_DC) /* {{{ */
{
	CURLcode cres, ctres, crres;
	CURL *curl;
	struct curl_slist *curl_headers = NULL;
	long l_code, response_code = -1;
	double d_code;
	zval *info, **zca_info, **zca_path;
	void *p_cur;
	char *s_code, *cur_key, *content_type = NULL, *bufz = NULL;
	char *auth_type = NULL;
	uint cur_key_len, sslcheck;
	ulong num_key;
	smart_str rheader = {0};

	auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));
	zca_info = soo_get_property(soo, OAUTH_ATTR_CA_INFO TSRMLS_CC);
	zca_path = soo_get_property(soo, OAUTH_ATTR_CA_PATH TSRMLS_CC);
	sslcheck = soo->sslcheck;

	curl = curl_easy_init();

	if (request_headers) {
		for (zend_hash_internal_pointer_reset(request_headers);
				zend_hash_get_current_data(request_headers, (void **)&p_cur) == SUCCESS;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key is used */
			if (HASH_KEY_IS_STRING==zend_hash_get_current_key_ex(request_headers, &cur_key, &cur_key_len, &num_key, 0, NULL)) {
				smart_str_appends(&rheader, cur_key);
				smart_str_appends(&rheader, ": ");
				smart_str_appends(&rheader, Z_STRVAL_PP((zval **)p_cur));
				smart_str_0(&rheader);
				curl_headers = curl_slist_append(curl_headers, rheader.c);
				smart_str_free(&rheader);
			}
		}
	}

	if (payload->len) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload->c);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload->len);
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* the fetch method takes precedence so figure it out after we've added the OAuth params */
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method);

	/* Disable sending the 100 Expect header for POST requests */
	/* Other notes: if there is a redirect the POST becomes a GET request, see curl_easy_setopt(3) and the CURLOPT_POSTREDIR option for more information */
	curl_headers = curl_slist_append(curl_headers, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, soo_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, soo);
	if(!sslcheck) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	} else {
		if(zca_path && Z_STRLEN_PP(zca_path)) {
			curl_easy_setopt(curl, CURLOPT_CAPATH, Z_STRVAL_PP(zca_path));
		}
		if(zca_info && Z_STRLEN_PP(zca_info)) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, Z_STRVAL_PP(zca_info));
		}
	}
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, soo_read_header);
	curl_easy_setopt(curl, CURLOPT_WRITEHEADER, soo);
	if(soo->debug) {
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	}
#if defined(ZTS)
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
#endif

#if LIBCURL_VERSION_NUM >= 0x071304
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, OAUTH_PROTOCOLS_ALLOWED);
#endif

	smart_str_free(&soo->lastresponse);

	if(soo->debug) {
		if(soo->debug_info->sbs) {
			FREE_DEBUG_INFO(soo->debug_info);
		}
		INIT_DEBUG_INFO(soo->debug_info);
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, oauth_debug_handler);
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, soo->debug_info);
	}

	cres = curl_easy_perform(curl);
	smart_str_0(&soo->lastresponse);

	if (curl_headers) {
		curl_slist_free_all(curl_headers);
	}

	if (CURLE_OK == cres) {
		ctres = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (CURLE_OK == crres && ctres == CURLE_OK) {
			ALLOC_INIT_ZVAL(info);
			array_init(info);

			CAAL("http_code", response_code);

			if (HTTP_IS_REDIRECT(response_code) && soo->last_location_header) {
				CAAS("redirect_url", soo->last_location_header);
			}

			if (content_type != NULL) {
				CAAS("content_type", content_type);
			}
			if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &s_code) == CURLE_OK) {
				CAAS("url", s_code);
			}

			if (curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &l_code) == CURLE_OK) {
				CAAL("header_size", l_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &l_code) == CURLE_OK) {
				CAAL("request_size", l_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_FILETIME, &l_code) == CURLE_OK) {
				CAAL("filetime", l_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &l_code) == CURLE_OK) {
				CAAL("ssl_verify_result", l_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &l_code) == CURLE_OK) {
				CAAL("redirect_count", l_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME,&d_code) == CURLE_OK) {
				CAAD("total_time", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &d_code) == CURLE_OK) {
				CAAD("namelookup_time", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &d_code) == CURLE_OK) {
				CAAD("connect_time", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &d_code) == CURLE_OK) {
				CAAD("pretransfer_time", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &d_code) == CURLE_OK){
				CAAD("size_upload", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &d_code) == CURLE_OK){
				CAAD("size_download", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &d_code) == CURLE_OK){
				CAAD("speed_download", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &d_code) == CURLE_OK){
				CAAD("speed_upload", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d_code) == CURLE_OK) {
				CAAD("download_content_length", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_UPLOAD, &d_code) == CURLE_OK) {
				CAAD("upload_content_length", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &d_code) == CURLE_OK){
				CAAD("starttransfer_time", d_code);
			}
			if (curl_easy_getinfo(curl, CURLINFO_REDIRECT_TIME, &d_code) == CURLE_OK){
				CAAD("redirect_time", d_code);
			}

			so_set_response_info(soo->properties, info);
		}
	} else {
		spprintf(&bufz, 0, "making the request failed (%s)", curl_easy_strerror(cres));
		soo_handle_error(-1, bufz, soo->lastresponse.c TSRMLS_CC);
		efree(bufz);
	}
	if(soo->debug) {
		oauth_set_debug_info(soo TSRMLS_CC);
	}
	curl_easy_cleanup(curl);
	return response_code;
}
/* }}} */

static void make_standard_query(HashTable *ht, php_so_object *soo TSRMLS_DC) /* {{{ */
{
	char *tb;
	time_t now;

	now = time(NULL);
	/* XXX allow caller to set timestamp, if none set, then default to "now" */
	spprintf(&tb, 0, "%d", (int)now);
	add_arg_for_req(ht, OAUTH_PARAM_CONSUMER_KEY, Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_CONSUMER_KEY TSRMLS_CC)) TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_SIGNATURE_METHOD, Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_SIGMETHOD TSRMLS_CC)) TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_NONCE, Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_OAUTH_NONCE TSRMLS_CC)) TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_TIMESTAMP, tb TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_VERSION, Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC)) TSRMLS_CC);
	efree(tb);
}
/* }}} */

/*
Returns the default http method to use with the different auth types
*/
static const char *oauth_get_http_method(php_so_object *soo, const char *http_method TSRMLS_DC) /* {{{ */
{
	char *auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));

	if (0==strcmp(auth_type, OAUTH_AUTH_TYPE_FORM)) {
		return OAUTH_HTTP_METHOD_POST;
	} else if (!http_method) {
		return OAUTH_HTTP_METHOD_GET;
	}
	return http_method;
}
/* }}} */

/*
Modifies (and returns) passed url parameter to be used for additional parameter appending
*/
static smart_str *http_prepare_url_concat(smart_str *surl) /* {{{ */
{
	smart_str_0(surl);
	if (!strchr(surl->c, '?')) {
		smart_str_appendc(surl, '?');
	} else {
		smart_str_appendc(surl, '&');
	}
	return surl;
}
/* }}} */

/*
Modifies passed url based on the location header that was received in the response headers, depending on whether the redirection was relative or absolute
*/
static void oauth_apply_url_redirect(smart_str *surl, const char *location) /* {{{ */
{
	php_url *urlparts;

	// determine whether location is relative
	if ('/'==*location) {
		urlparts = php_url_parse_ex(surl->c, surl->len);

		// rebuild url from scratch
		smart_str_free(surl);
		if (urlparts->scheme) {
			smart_str_appends(surl, urlparts->scheme);
			smart_str_appends(surl, "://");
		}
		if (urlparts->host) {
			smart_str_appends(surl, urlparts->host);
		}
		if (urlparts->port) {
			smart_str_appendc(surl, ':');
			smart_str_append_unsigned(surl, urlparts->port);
		}
		smart_str_appends(surl, location);

		php_url_free(urlparts);
	} else {
		smart_str_free(surl);
		smart_str_appends(surl, location);
	}
}
/* }}} */

/*
Prepares the request elements to be used by make_req(); this should allow for supporting streams in the future
*/
static long oauth_fetch(php_so_object *soo, const char *url, const char *method, zval *request_params, zval *request_headers, HashTable *init_oauth_args, int fetch_flags TSRMLS_DC) /* {{{ */
{
	char *sbs = NULL, *sig = NULL, *auth_type, *bufz = NULL;
	const char *final_http_method;
	zval **token = NULL, **cs;
	zval *ts = NULL, **token_secret = NULL;
	zval *zret;
	HashTable *oauth_args = NULL;
	HashTable *rargs = NULL, *rheaders = NULL;
	long http_response_code;
	smart_str surl = {0}, payload = {0}, postdata = {0};
	uint is_redirect = FALSE, follow_redirects;

	auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));
	final_http_method = oauth_get_http_method(soo, method TSRMLS_CC);

	if (!strcasecmp(auth_type, OAUTH_AUTH_TYPE_FORM) && strcasecmp(final_http_method, OAUTH_HTTP_METHOD_POST)) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "auth type is set to HTTP POST with a non-POST http method, use setAuthType to put OAuth parameters somewhere else in the request", NULL TSRMLS_CC);
	}

	follow_redirects = soo->follow_redirects;
	soo->redirects = 0;

	/* request_params can be either NULL, a string containing arbitrary text (such as XML) or an array */
	if (request_params) {
		switch (Z_TYPE_P(request_params)) {
		case IS_ARRAY:
			rargs = HASH_OF(request_params);
			oauth_http_build_query(&postdata, rargs, FALSE, PARAMS_FILTER_NONE);
			break;
		case IS_STRING:
			smart_str_appendl(&postdata, Z_STRVAL_P(request_params), Z_STRLEN_P(request_params));
			break;
		}
	}

	/* additional http headers can be passed */
	if (!request_headers) {
		ALLOC_HASHTABLE(rheaders);
		zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
	} else {
		SEPARATE_ZVAL(&request_headers);
		rheaders = HASH_OF(request_headers);
	}

	/* initialize base url */
	smart_str_appends(&surl, url);

	do {
		/* initialize response code */
		http_response_code = -1;

		/* prepare oauth arguments to be signed */
		ALLOC_HASHTABLE(oauth_args);
		zend_hash_init(oauth_args, 0, NULL, ZVAL_PTR_DTOR, 0);

		/* an array can be passed to prime special oauth parameters */
		if (init_oauth_args) {
			zval *tmp_copy;
			/* populate oauth_args with given parameters */
			zend_hash_copy(oauth_args, init_oauth_args, (copy_ctor_func_t) zval_add_ref, (void *) &tmp_copy, sizeof(zval *));
		}

		/* fill in the standard set of oauth parameters */
		make_standard_query(oauth_args, soo TSRMLS_CC);

		/* use token where applicable */
		if (fetch_flags & OAUTH_FETCH_USETOKEN) {
			token = soo_get_property(soo, OAUTH_ATTR_TOKEN TSRMLS_CC);
			if (token) {
				add_arg_for_req(oauth_args, OAUTH_PARAM_TOKEN, Z_STRVAL_PP(token) TSRMLS_CC);
			}
		}

		/* generate sig base on the semi-final url */
		smart_str_0(&surl);
		sbs = oauth_generate_sig_base(soo, final_http_method, surl.c, oauth_args, rargs TSRMLS_CC);
		if (!sbs) {
			FREE_ARGS_HASH(oauth_args);
			soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url, unable to generate signature base string", NULL TSRMLS_CC);
			break;
		}

		cs = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
		SEPARATE_ZVAL(cs);

		/* determine whether token should be used to sign the request */
		if (fetch_flags & OAUTH_FETCH_USETOKEN) {
			token_secret = soo_get_property(soo, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
			if (token_secret && Z_STRLEN_PP(token_secret) > 0) {
				ts = *token_secret;
			}
		}

		/* sign the request */
		sig = soo_hmac_sha1(sbs, *cs, ts TSRMLS_CC);
		efree(sbs);
		if (!sig) {
			FREE_ARGS_HASH(oauth_args);
			break;
		}

		/* and add signature to the oauth parameters */
		add_arg_for_req(oauth_args, OAUTH_PARAM_SIGNATURE, sig TSRMLS_CC);
		efree(sig);

		if (!strcmp(final_http_method, OAUTH_HTTP_METHOD_GET)) {
			/* GET request means to extend the url, but not for redirects obviously */
			if (!is_redirect && postdata.len) {
				smart_str_append(http_prepare_url_concat(&surl), &postdata);
			}
		} else {
			/* otherwise populate post data */
			smart_str_append(&payload, &postdata);
		}

		if (!strcmp(auth_type, OAUTH_AUTH_TYPE_FORM)) {
			/* append/set post data with oauth parameters */
			oauth_http_build_query(&payload, oauth_args, payload.len, PARAMS_FILTER_NONE);
			smart_str_0(&payload);
		} else if (!strcmp(auth_type, OAUTH_AUTH_TYPE_URI)) {
			/* extend url request with oauth parameters */
			if (!is_redirect) {
				oauth_http_build_query(http_prepare_url_concat(&surl), oauth_args, FALSE, PARAMS_FILTER_NONE);
			}
			/* TODO look into merging oauth parameters if they occur in the current url */
		} else if (!strcmp(auth_type, OAUTH_AUTH_TYPE_AUTHORIZATION)) {
			/* add http header with oauth parameters */
			oauth_add_signature_header(rheaders, oauth_args TSRMLS_CC);
		}

		/* finalize endpoint url */
		smart_str_0(&surl);

		http_response_code = make_req(soo, surl.c, &payload, final_http_method, rheaders TSRMLS_CC);

		FREE_ARGS_HASH(oauth_args);
		smart_str_free(&payload);

		is_redirect = HTTP_IS_REDIRECT(http_response_code) && soo->last_location_header;
		if (is_redirect) {
			if (follow_redirects) {
				if (soo->redirects >= OAUTH_MAX_REDIRS) {
					spprintf(&bufz, 0, "max redirections exceeded (max: %ld last redirect url: %s)", OAUTH_MAX_REDIRS, soo->last_location_header);
					MAKE_STD_ZVAL(zret);
					if (soo->lastresponse.len) {
						ZVAL_STRING(zret, soo->lastresponse.c, 1);
					} else {
						ZVAL_STRING(zret, "", 1);
					}
					so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);
					soo_handle_error(http_response_code, bufz, soo->lastresponse.c TSRMLS_CC);
					efree(bufz);
					/* set http_response_code to error value */
					http_response_code = -1;
					break;
				} else {
					++soo->redirects;
					oauth_apply_url_redirect(&surl, soo->last_location_header);
					smart_str_0(&surl);
					final_http_method = OAUTH_HTTP_METHOD_GET;
				}
			}
		} else if (http_response_code < 200 || http_response_code > 206) {
			spprintf(&bufz, 0, "Invalid auth/bad request (got a %ld, expected HTTP/1.1 20X or a redirect)", http_response_code);
			MAKE_STD_ZVAL(zret);
			if(soo->lastresponse.c) {
				ZVAL_STRING(zret, soo->lastresponse.c, 1);
			} else {
				ZVAL_STRING(zret, "", 1);
			}
			so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);
			soo_handle_error(http_response_code, bufz, soo->lastresponse.c TSRMLS_CC);
			efree(bufz);
			/* set http_response_code to error value */
			http_response_code = -1;
			break;
		} else {
			/* valid response, time to get out of this loop */
		}
	} while (is_redirect);

	smart_str_free(&surl);
	smart_str_free(&postdata);
	FREE_ARGS_HASH(rheaders);

	return http_response_code;
}
/* }}} */

/* {{{ proto string oauth_urlencode(string uri)
   URI encoding according to RFC 3986, note: is not utf8 capable until the underlying phpapi is */
PHP_FUNCTION(oauth_urlencode)
{
	int uri_len;
	char *uri;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE) {
		return;
	}

	if (uri_len < 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid uri length (0)");
		RETURN_NULL();
	}
	RETURN_STRING(oauth_url_encode(uri), 0);
}
/* }}} */

/* {{{ proto string oauth_get_sbs(string http_method, string uri, array parameters)
   Get a signature base string */
PHP_FUNCTION(oauth_get_sbs)
{
	char *uri, *http_method;
	int uri_len, http_method_len;
	zval *req_params;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &http_method, &http_method_len, &uri, &uri_len, &req_params) == FAILURE) {
		return;
	}

	if (uri_len < 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid uri length (0)");
		RETURN_NULL();
	}

	if (http_method_len < 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid http method length (0)");
		RETURN_NULL();
	}
	
	RETURN_STRING(oauth_generate_sig_base(NULL, http_method, uri, NULL, HASH_OF(req_params) TSRMLS_CC), 0);
}
/* }}} */

/* only hmac-sha1 is supported at the moment (it is the most common implementation), still need to lay down the ground work for supporting plaintext and others */

/* {{{ proto void OAuth::__construct(string consumer_key, string consumer_secret [, string signature_method, [, string auth_type ]])
   Instantiate a new OAuth object */
SO_METHOD(__construct)
{
	HashTable *hasht;
	char *ck, *cs, *sig_method = NULL,*auth_method = NULL;
	zval *zck, *zcs, *zsm, *zam, *zver;
	int ck_len, cs_len, sig_method_len = 0, auth_method_len = 0;
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|ss", &ck, &ck_len, &cs, &cs_len, &sig_method, &sig_method_len, &auth_method, &auth_method_len) == FAILURE) {
		return;
	}

	memset(soo->last_location_header, 0, OAUTH_MAX_HEADER_LEN);
	soo->redirects = 0;
	soo->debug = 0;
	soo->debug_info = emalloc(sizeof(php_so_debug));
	soo->debug_info->sbs = NULL;
	soo->debugArr = NULL;

	INIT_DEBUG_INFO(soo->debug_info);

	zend_update_property_null(soo_class_entry, getThis(), "debugInfo", sizeof("debugInfo") - 1 TSRMLS_CC);

	TSRMLS_SET_CTX(soo->thread_ctx);


	if(!ck_len) {
		php_error(E_ERROR, "the consumer key cannot be empty");
		return;
	}

	if(!cs_len) {
		php_error(E_ERROR, "the consumer secret cannot be empty");
		return;
	}

	if (!sig_method_len) {
		sig_method = OAUTH_SIG_METHOD_HMACSHA1;
	}

	if (!auth_method_len) {
		auth_method = OAUTH_AUTH_TYPE_AUTHORIZATION;
	}

	if (soo->properties) {
		zend_hash_clean(soo->properties);
		hasht = soo->properties;
	} else {
		ALLOC_HASHTABLE(hasht);
		zend_hash_init(hasht, 0, NULL, ZVAL_PTR_DTOR, 0);
		soo->properties = hasht;
	}

	MAKE_STD_ZVAL(zck);
	ZVAL_STRING(zck, ck, 1);
	if (soo_set_property(soo, zck, OAUTH_ATTR_CONSUMER_KEY TSRMLS_CC) != SUCCESS) {
		return;
	}

	if (cs_len > 0) {
		MAKE_STD_ZVAL(zcs);
		ZVAL_STRING(zcs, oauth_url_encode(cs), 0);

		if (soo_set_property(soo, zcs, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC) != SUCCESS) {
			return;
		}
	}
	MAKE_STD_ZVAL(zsm);
	ZVAL_STRING(zsm, sig_method, 1);
	if (soo_set_property(soo, zsm, OAUTH_ATTR_SIGMETHOD TSRMLS_CC) != SUCCESS) {
		return;
	}

	MAKE_STD_ZVAL(zam);
	ZVAL_STRING(zam, auth_method, 1);
	if (soo_set_property(soo, zam, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC) != SUCCESS) {
		return;
	}

	MAKE_STD_ZVAL(zver);
	ZVAL_STRING(zver, OAUTH_DEFAULT_VERSION, 1);
	if (soo_set_property(soo, zver, OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC) != SUCCESS) {
		return;
	} 

	soo->debug = 0;
	soo->sslcheck = 1;
	soo->follow_redirects = 1;

	soo->lastresponse.c = NULL;
}
/* }}} */

/* {{{ proto void OAuth::__destruct(void)
   clean up of OAuth object */
SO_METHOD(__destruct)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	oauth_prop_hash_dtor(soo TSRMLS_CC);

	if (soo->debug_info) {
		FREE_DEBUG_INFO(soo->debug_info);
		if (soo->debug_info->sbs) {
			efree(soo->debug_info->sbs);
		}
		efree(soo->debug_info);
		soo->debug_info = NULL;
	}

	if(soo->debugArr) {
		zval_ptr_dtor(&soo->debugArr);
	}
}
/* }}} */

/* {{{ proto array OAuth::setCAPath(string ca_path, string ca_info)
   Set the Certificate Authority information */
SO_METHOD(setCAPath)
{
	php_so_object *soo;
	char *ca_path, *ca_info;
	int ca_path_len, ca_info_len;
	zval *zca_path, *zca_info;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss", &ca_path, &ca_path_len, &ca_info, &ca_info_len) == FAILURE) {
		return;
	}

	if (ca_path_len) {
		MAKE_STD_ZVAL(zca_path);
		ZVAL_STRINGL(zca_path, ca_path, ca_path_len, 1);
		if (soo_set_property(soo, zca_path, OAUTH_ATTR_CA_PATH TSRMLS_CC) != SUCCESS) {
			RETURN_NULL();
		}
	}

	if (ca_info_len) {
		MAKE_STD_ZVAL(zca_info);
		ZVAL_STRINGL(zca_info, ca_info, ca_info_len, 1);
		if (soo_set_property(soo, zca_info, OAUTH_ATTR_CA_INFO TSRMLS_CC) != SUCCESS) {
			RETURN_NULL();
		}
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array OAuth::getCAPath(void)
   Get the Certificate Authority information */
SO_METHOD(getCAPath)
{
	/* perhaps make this information available via members too? */
	php_so_object *soo;
	zval **zca_path, **zca_info;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	zca_info = soo_get_property(soo, OAUTH_ATTR_CA_INFO TSRMLS_CC);
	zca_path = soo_get_property(soo, OAUTH_ATTR_CA_PATH TSRMLS_CC);

	array_init(return_value);

	if (zca_info || zca_path) {
		if(zca_info) {
			add_assoc_stringl(return_value, "ca_info", Z_STRVAL_PP(zca_info), Z_STRLEN_PP(zca_info), 1);
		}

		if(zca_path) {
			add_assoc_stringl(return_value, "ca_path", Z_STRVAL_PP(zca_path), Z_STRLEN_PP(zca_path), 1);
		}
	}
}
/* }}} */

/* {{{ proto array OAuth::getRequestToken(string request_token_url [, string callback_url ])
   Get request token */
SO_METHOD(getRequestToken)
{
	php_so_object *soo;
	zval *zret = NULL;
	char *url, *callback_url = NULL;
	int url_len = 0, callback_url_len = 0;
	long retcode;
	HashTable *args = NULL;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &url, &url_len, &callback_url, &callback_url_len) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid request token url length", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	if (callback_url) {
		ALLOC_HASHTABLE(args);
		zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
		if (callback_url_len > 0) {
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, callback_url TSRMLS_CC);
		} else {
			// empty callback url specified, treat as 1.0a
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, OAUTH_CALLBACK_OOB TSRMLS_CC);
		}
	}

	retcode = oauth_fetch(soo, url, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), NULL, NULL, args, 0 TSRMLS_CC);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.c) {
		array_init(return_value);
		MAKE_STD_ZVAL(zret);
		ZVAL_STRINGL(zret, soo->lastresponse.c, soo->lastresponse.len, 1);
		so_set_response_args(soo->properties, zret, return_value TSRMLS_CC);
		return;
	}
	RETURN_NULL();
}
/* }}} */

/* {{{ proto bool OAuth::enableRedirects(void)
   Follow and sign redirects automatically (enabled by default) */
SO_METHOD(enableRedirects)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->follow_redirects = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableRedirects(void)
   Don't follow redirects automatically, thus allowing the request to be manually redirected (enabled by default) */
SO_METHOD(disableRedirects)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	soo->follow_redirects = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableDebug(void)
   Disable debug mode */
SO_METHOD(disableDebug)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->debug = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableDebug(void)
   Enable debug mode, will verbosely output http information about requests */
SO_METHOD(enableDebug)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->debug = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableSSLChecks(void)
   Enable SSL verification for requests, enabled by default */
SO_METHOD(enableSSLChecks)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->sslcheck = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableSSLChecks(void)
   Disable SSL verification for requests (be careful using this for production) */
SO_METHOD(disableSSLChecks)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->sslcheck = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::setVersion(string version)
   Set oauth_version for requests (default 1.0) */
SO_METHOD(setVersion)
{
	php_so_object *soo;
	int ver_len = 0;
	char *vers;
	zval *zver;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &vers, &ver_len) == FAILURE) {
		return;
	}

	if (ver_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid version", NULL TSRMLS_CC);
		RETURN_NULL();
	}

	MAKE_STD_ZVAL(zver);
	ZVAL_STRING(zver, vers, 1);
	if (soo_set_property(soo, zver, OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool OAuth::setAuthType(string auth_type)
   Set the manner in which to send oauth parameters */
SO_METHOD(setAuthType)
{
	php_so_object *soo;
	int auth_len;
	char *auth;
	zval *zauth;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &auth, &auth_len) == FAILURE) {
		return;
	}

	/* XXX check to see if we actually support the type rather than just the length */
	if (auth_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL TSRMLS_CC);
		RETURN_NULL();
	}

	MAKE_STD_ZVAL(zauth);
	ZVAL_STRING(zauth, auth, 1);
	if (soo_set_property(soo, zauth, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC) == SUCCESS) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool OAuth::setNonce(string nonce)
   Set oauth_nonce for subsequent requests, if none is set a random nonce will be generated using uniqid */
SO_METHOD(setNonce)
{
	php_so_object *soo;
	int nonce_len;
	char *nonce;
	zval *zonce;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &nonce, &nonce_len) == FAILURE) {
		return;
	}

	if (nonce_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid nonce", NULL TSRMLS_CC);
		RETURN_NULL();
	}

	MAKE_STD_ZVAL(zonce);
	ZVAL_STRING(zonce, nonce, 1);

	if (soo_set_property(soo, zonce, OAUTH_ATTR_OAUTH_USER_NONCE TSRMLS_CC)) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool OAuth::setToken(string token, string token_secret)
   Set a request or access token and token secret to be used in subsequent requests */
SO_METHOD(setToken)
{
	php_so_object *soo;
	int token_len, token_secret_len;
	char *token, *token_secret;
	zval *t,*ts;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &token, &token_len, &token_secret, &token_secret_len) == FAILURE) {
		return;
	}

	MAKE_STD_ZVAL(t);
	ZVAL_STRING(t, token, 1);
	soo_set_property(soo, t, OAUTH_ATTR_TOKEN TSRMLS_CC);

	if (token_secret_len > 1) {
		MAKE_STD_ZVAL(ts);
		ZVAL_STRING(ts, oauth_url_encode(token_secret), 0);
		soo_set_property(soo, ts, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::fetch(string protected_resource_url [, string|array extra_parameters [, string request_type [, array request_headers]]])
   fetch a protected resource, pass in extra_parameters (array(name => value) or "custom body") */
SO_METHOD(fetch)
{
	php_so_object *soo;
	int fetchurl_len, http_method_len = 0;
	char *fetchurl;
	zval *zret = NULL, *request_args = NULL, *request_headers = NULL;
	char *http_method = NULL;
	long retcode;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zsa", &fetchurl, &fetchurl_len, &request_args, &http_method, &http_method_len, &request_headers) == FAILURE) {
		return;
	}

	if (fetchurl_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url length", NULL TSRMLS_CC);
		RETURN_NULL();
	}

	retcode = oauth_fetch(soo, fetchurl, http_method, request_args, request_headers, NULL, OAUTH_FETCH_USETOKEN TSRMLS_CC);

	MAKE_STD_ZVAL(zret);
	ZVAL_STRINGL(zret, soo->lastresponse.c, soo->lastresponse.len, 1);
	so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);

	if (retcode < 0 || soo->lastresponse.c == NULL) {
		RETURN_NULL();
	} else {
		RETURN_BOOL(TRUE);
	}
}
/* }}} */

/* {{{ proto array OAuth::getAccessToken(string access_token_url [, string auth_session_handle [, string auth_verifier ]])
	Get access token, 
	If the server supports Scalable OAuth pass in the auth_session_handle to refresh the token (http://wiki.oauth.net/ScalableOAuth)
	For 1.0a implementation, a verifier token must be passed; this token is not passed unless a value is explicitly assigned via the function arguments or $_GET/$_POST['oauth_verifier'] is set
*/
SO_METHOD(getAccessToken)
{
	php_so_object *soo;
	int aturi_len = 0, ash_len = 0, verifier_len = 0;
	char *aturi, *ash, *verifier;
	zval *zret = NULL;
	HashTable *args = NULL;
	long retcode;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ss", &aturi, &aturi_len, &ash, &ash_len, &verifier, &verifier_len) == FAILURE) {
		return;
	}

	if (aturi_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid access token url length", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	if (!verifier_len) {
		/* try to get from _GET/_POST */
		get_request_param(OAUTH_PARAM_VERIFIER, &verifier, &verifier_len TSRMLS_CC);
	}

	if (ash_len > 0 || verifier_len > 0) {
		ALLOC_HASHTABLE(args);
		zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
		if (ash_len > 0) {
			add_arg_for_req(args, OAUTH_PARAM_ASH, ash TSRMLS_CC);
		}
		if (verifier_len > 0) {
			add_arg_for_req(args, OAUTH_PARAM_VERIFIER, verifier TSRMLS_CC);
		}
	}

	retcode = oauth_fetch(soo, aturi, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), NULL, NULL, args, OAUTH_FETCH_USETOKEN TSRMLS_CC);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.c) {
		array_init(return_value);
		MAKE_STD_ZVAL(zret);
		ZVAL_STRINGL(zret, soo->lastresponse.c, soo->lastresponse.len, 1);
		so_set_response_args(soo->properties, zret, return_value TSRMLS_CC);
		return;
	}
	RETURN_NULL();
}
/* }}} */

/* {{{ proto array OAuth::getLastResponseInfo(void)
   Get information about the last response */
SO_METHOD(getLastResponseInfo)
{
	php_so_object *soo;
	zval **data_ptr;
	ulong hf = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo = fetch_so_object(getThis() TSRMLS_CC);

	hf = zend_hash_func(OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO));

	if (zend_hash_quick_find(soo->properties, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO), hf, (void *)&data_ptr) == SUCCESS) {
		if (Z_TYPE_PP(data_ptr) == IS_ARRAY) {
			convert_to_array_ex(data_ptr);
		}
		RETURN_ZVAL(*data_ptr, 1, 0);
	}
	RETURN_NULL();
}
/* }}} */

/* {{{ proto array OAuth::getLastResponse(void)
   Get last response */
SO_METHOD(getLastResponse)
{
	php_so_object *soo;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (soo->lastresponse.c) {
		RETURN_STRINGL(soo->lastresponse.c, soo->lastresponse.len, 1);
	}
#if jawed_0
	void *p_data_ptr;
	zval **data_ptr;
	ulong hf = 0;
	ulong hlen = 0;
	char *hkey = OAUTH_ATTR_LAST_RES;
	hkey = OAUTH_RAW_LAST_RES;
	hlen = strlen(hkey)+1;
	hf = zend_hash_func(hkey,hlen);
	if (zend_hash_quick_find(soo->properties, hkey, hlen, hf, &p_data_ptr) == SUCCESS) {
		data_ptr = p_data_ptr;
		RETURN_STRING(Z_STRVAL_P(*data_ptr), 0);
	}
	RETURN_NULL();
#endif
}
/* }}} */

/* {{{ arginfo */
OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_urlencode, 0, 0, 1)
	ZEND_ARG_INFO(0, uri)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_sbs, 0, 0, 1)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, uri)
	ZEND_ARG_INFO(0, parameters)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth__construct, 0, 0, 2)
	ZEND_ARG_INFO(0, consumer_key)
	ZEND_ARG_INFO(0, consumer_secret)
	ZEND_ARG_INFO(0, signature_method)
	ZEND_ARG_INFO(0, auth_type)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getrequesttoken, 0, 0, 1)
	ZEND_ARG_INFO(0, request_token_url)
	ZEND_ARG_INFO(0, callback_url)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setversion, 0, 0, 1)
	ZEND_ARG_INFO(0, version)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setauthtype, 0, 0, 1)
	ZEND_ARG_INFO(0, auth_type)
ZEND_END_ARG_INFO();

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setnonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setcapath, 0, 0, 2)
	ZEND_ARG_INFO(0, ca_path)
	ZEND_ARG_INFO(0, ca_info)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settoken, 0, 0, 2)
	ZEND_ARG_INFO(0, token)
	ZEND_ARG_INFO(0, token_secret)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_fetch, 0, 0, 1)
	ZEND_ARG_INFO(0, protected_resource_url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, request_headers)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getaccesstoken, 0, 0, 1)
	ZEND_ARG_INFO(0, access_token_url)
	ZEND_ARG_INFO(0, auth_session_handle)
	ZEND_ARG_INFO(0, auth_verifier)
ZEND_END_ARG_INFO()
/* }}} */

static zend_function_entry so_functions[] = { /* {{{ */
	SO_ME(__construct,			arginfo_oauth__construct,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
	SO_ME(getRequestToken,		arginfo_oauth_getrequesttoken,	ZEND_ACC_PUBLIC)
	SO_ME(getAccessToken,		arginfo_oauth_getaccesstoken,	ZEND_ACC_PUBLIC)
	SO_ME(getLastResponse,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(getLastResponseInfo,	arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(setToken,				arginfo_oauth_settoken,			ZEND_ACC_PUBLIC)
	SO_ME(setVersion,			arginfo_oauth_setversion,		ZEND_ACC_PUBLIC)
	SO_ME(setAuthType,			arginfo_oauth_setauthtype,		ZEND_ACC_PUBLIC)
	SO_ME(setNonce,				arginfo_oauth_setnonce,			ZEND_ACC_PUBLIC)
	SO_ME(fetch,				arginfo_oauth_fetch,			ZEND_ACC_PUBLIC)
	SO_ME(enableDebug,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableDebug,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(enableSSLChecks,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableSSLChecks,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(enableRedirects,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableRedirects,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(setCAPath,			arginfo_oauth_setcapath,		ZEND_ACC_PUBLIC)
	SO_ME(getCAPath,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(__destruct,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */

static zval *oauth_read_member(zval *obj, zval *mem, int type TSRMLS_DC) /* {{{ */
{
	zval *return_value;
	php_so_object *soo;

	soo = fetch_so_object(obj TSRMLS_CC);

	if(!strcmp(Z_STRVAL_P(mem),"debug")) {
		MAKE_STD_ZVAL(return_value);
		ZVAL_BOOL(return_value, soo->debug);
	} else if(!strcmp(Z_STRVAL_P(mem),"sslChecks")) {
		MAKE_STD_ZVAL(return_value);
		ZVAL_BOOL(return_value, soo->sslcheck);
	} else {
		return zend_get_std_object_handlers()->read_property(obj, mem, type TSRMLS_CC);
	}
	return return_value;
} /* }}} */

static void oauth_write_member(zval *obj, zval *mem, zval *value TSRMLS_DC) /* {{{ */
{
	char *property;
	php_so_object *soo;

	property = Z_STRVAL_P(mem);
	soo = fetch_so_object(obj TSRMLS_CC);

	if(!strcmp(property,"debug")) {
		soo->debug = Z_LVAL_P(value);
	} else if(!strcmp(property,"sslChecks")) {
		soo->sslcheck = Z_LVAL_P(value);
	} else {
		zend_get_std_object_handlers()->write_property(obj, mem, value TSRMLS_CC);
	}
} /* }}} */

/* {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION(oauth) 
{
	zend_class_entry soce, soo_ex_ce;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		return FAILURE;
	}

	INIT_CLASS_ENTRY(soce, "OAuth", so_functions);
	soce.create_object = new_so_object;

	soo_class_entry = zend_register_internal_class(&soce TSRMLS_CC);
	memcpy(&so_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	
	so_object_handlers.read_property = oauth_read_member;
	so_object_handlers.write_property = oauth_write_member;

	zend_declare_property_long(soo_class_entry, "debug", sizeof("debug")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(soo_class_entry, "sslChecks", sizeof("sslChecks")-1, 1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(soo_class_entry, "debugInfo", sizeof("debugInfo")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);


	INIT_CLASS_ENTRY(soo_ex_ce, "OAuthException", NULL);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 2)
	soo_exception_ce = zend_register_internal_class_ex(&soo_ex_ce, zend_exception_get_default(), NULL TSRMLS_CC);
#else
	soo_exception_ce = zend_register_internal_class_ex(&soo_ex_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
#endif
	zend_declare_property_null(soo_exception_ce, "lastResponse", sizeof("lastResponse")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

	REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_HMACSHA1", OAUTH_SIG_METHOD_HMACSHA1, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_AUTHORIZATION", OAUTH_AUTH_TYPE_AUTHORIZATION, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_URI", OAUTH_AUTH_TYPE_URI, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_FORM", OAUTH_AUTH_TYPE_FORM, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_NONE", OAUTH_AUTH_TYPE_FORM, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_GET", OAUTH_HTTP_METHOD_GET, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_POST", OAUTH_HTTP_METHOD_POST, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_PUT", OAUTH_HTTP_METHOD_PUT, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_HEAD", OAUTH_HTTP_METHOD_HEAD, CONST_CS | CONST_PERSISTENT); 
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
*/
PHP_MSHUTDOWN_FUNCTION(oauth) 
{
	soo_class_entry = NULL;
	soo_exception_ce = NULL;
	curl_global_cleanup();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
*/
PHP_MINFO_FUNCTION(oauth) 
{
	php_info_print_table_start();
	php_info_print_table_header(2, "OAuth support", "enabled");
	php_info_print_table_row(2, "PLAINTEXT support", "not supported");
	php_info_print_table_row(2, "RSA-SHA1 support", "not supported");
	php_info_print_table_row(2, "HMAC-SHA1 support", "enabled");
	php_info_print_table_row(2, "source version", "$Id$");
	php_info_print_table_row(2, "version", OAUTH_EXT_VER);
	php_info_print_table_end();
}
/* }}} */

/* TODO expose a function for base sig string */
zend_function_entry oauth_functions[] = { /* {{{ */
	PHP_FE(oauth_urlencode,		arginfo_oauth_urlencode)
	PHP_FE(oauth_get_sbs,		arginfo_oauth_sbs)
	{ NULL, NULL, NULL }
};
/* }}} */

/* {{{ oauth_module_entry */
zend_module_entry oauth_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	NULL,
	"OAuth",
	oauth_functions,
	PHP_MINIT(oauth),
	PHP_MSHUTDOWN(oauth),
	NULL,
	NULL,
	PHP_MINFO(oauth),
	OAUTH_EXT_VER,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#if COMPILE_DL_OAUTH
ZEND_GET_MODULE(oauth);
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

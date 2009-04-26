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
#define SO_ADD_SIG(f, b)									\
	add_arg_for_req(f,OAUTH_PARAM_SIGNATURE, b TSRMLS_CC);	\
	efree(b);
#define CLEANUP_CURL_AND_FORM(f,h)	\
	curl_easy_cleanup(h);			\
	curl_formfree(f);
#define FREE_ARGS_HASH(a)	\
	zend_hash_destroy(a);	\
	FREE_HASHTABLE(a);

/* this and code that uses it is from ext/curl/interface.c */
#define CAAL(s, v) add_assoc_long_ex(info, s, sizeof(s), (long) v);
#define CAAD(s, v) add_assoc_double_ex(info, s, sizeof(s), (double) v);
#define CAAS(s, v) add_assoc_string_ex(info, s, sizeof(s), (char *) (v ? v : ""), 1);

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

zend_class_entry *so_class_entry = NULL;

ZEND_DECLARE_MODULE_GLOBALS(oauth)

static PHP_GINIT_FUNCTION(oauth);

static zend_object_handlers so_object_handlers;

#if COMPILE_DL_OAUTH
ZEND_GET_MODULE(oauth);
#endif

static PHP_GINIT_FUNCTION(oauth) /* {{{ */
{
	oauth_globals->soo_exception_ce = NULL;
}
/* }}} */

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
	return (php_so_object *)zend_object_store_get_object(obj TSRMLS_CC);
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
	zend_class_entry *dex = zend_exception_get_default(TSRMLS_C), *soox = OAUTH(soo_exception_ce);

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

	if (ts && Z_STRLEN_P(ts) > 0) {
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
	//zval **old_value = NULL;

	prop_len = strlen(prop_name);
	h = zend_hash_func(prop_name, prop_len+1);

	return zend_hash_quick_update(soo->properties, prop_name, prop_len+1, h, (void *)&prop, sizeof(zval *), NULL);
}
/* }}} */

static char *oauth_url_encode(char *url) /* {{{ */
{
	char *urlencoded, *ret;
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

				smart_str_appends(s, arg_key);
				smart_str_appendc(s, '=');
				smart_str_appends(s, param_value);

				efree(arg_key);
				efree(param_value);
				prepend_amp = TRUE;
				++numargs;
			}
		}
	}
	return numargs;
}

/*
 * This function does not currently care to respect parameter precedence, in the sense that if a common param is defined
 * in POST/GET or Authorization header, the precendence is defined by: OAuth Core 1.0 section 9.1.1
 */

static char *oauth_generate_sig_base(php_so_object *soo, const char *http_method, char *uri, HashTable *post_args, HashTable *extra_args TSRMLS_DC) /* {{{ */
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
			fprintf(stderr, "Signature Base String: %s\n", bufz);
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

static CURLcode make_req(php_so_object *soo, char *url, HashTable *ht, const char *http_method, HashTable *request_headers TSRMLS_DC) /* {{{ */
{
	CURLcode cres, ctres, crres;
	CURL *curl;
	struct curl_slist *curl_headers = NULL;
	long l_code, response_code;
	double d_code;
	zval *info, *zret;
	void *p_cur, *p_kcur;
	zend_bool prepend_comma = FALSE;
	char *s_code, *cur_key, *content_type = NULL, *bufz = NULL;
	char *auth_type = NULL, *param_name = NULL, *param_val = NULL;
	uint cur_key_len, is_redirect, follow_redirects, sslcheck;
	ulong num_key;
	smart_str surl = {0}, sheader = {0}, rheader = {0}, post = {0};

	auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));
	follow_redirects = soo->follow_redirects;
	sslcheck = soo->sslcheck;

	curl = curl_easy_init();

	if (request_headers) {
		for (zend_hash_internal_pointer_reset(request_headers);
				zend_hash_get_current_data(request_headers, (void **)&p_cur) == SUCCESS;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key is used */
			if (HASH_KEY_IS_STRING!=zend_hash_get_current_key_ex(request_headers, &cur_key, &cur_key_len, &num_key, 0, NULL)) {
				curl_headers = curl_slist_append(curl_headers, Z_STRVAL_PP((zval **)p_cur));
			} else {
				smart_str_appends(&rheader, cur_key);
				smart_str_appends(&rheader, ": ");
				smart_str_appends(&rheader, Z_STRVAL_PP((zval **)p_cur));
				smart_str_0(&rheader);
				curl_headers = curl_slist_append(curl_headers, rheader.c);
				smart_str_free(&rheader);
			}
		}
	}

	if (!strcmp(auth_type, OAUTH_AUTH_TYPE_FORM)) {
		oauth_http_build_query(&post, ht, FALSE, PARAMS_FILTER_NONE);
		smart_str_0(&post);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post.c);

		if(soo->debug) {
			fprintf(stderr,"POSTFIELDS: %s\n", post.c);
		}

		curl_easy_setopt(curl, CURLOPT_URL, url);
	} else if (!strcmp(auth_type, OAUTH_AUTH_TYPE_URI)) {
		smart_str_appends(&surl, url);

		if (strstr(url, "?") == NULL) {
			smart_str_appendc(&surl, '?');
		} else {
			smart_str_appendc(&surl, '&');
		}

		oauth_http_build_query(&surl, ht, FALSE, PARAMS_FILTER_NON_OAUTH);
		smart_str_0(&surl);

		curl_easy_setopt(curl, CURLOPT_URL, surl.c);
	} else if (!strcmp(auth_type, OAUTH_AUTH_TYPE_AUTHORIZATION)) {
		smart_str_appends(&sheader, "Authorization: OAuth ");

		for (zend_hash_internal_pointer_reset(ht);
				zend_hash_get_current_data(ht, (void **)&p_kcur) == SUCCESS;
				zend_hash_move_forward(ht)) {
			zend_hash_get_current_key_ex(ht, &cur_key, &cur_key_len, &num_key, 0, NULL);

			if (!strncmp(OAUTH_PARAM_PREFIX, cur_key, OAUTH_PARAM_PREFIX_LEN)) {
				if (prepend_comma) {
					smart_str_appendc(&sheader, ',');
				}
				param_name = oauth_url_encode(cur_key);
				param_val = oauth_url_encode(Z_STRVAL_PP((zval **)p_kcur));

				smart_str_appends(&sheader, param_name);
				smart_str_appendc(&sheader, '=');
				smart_str_appends(&sheader, "\"");
				smart_str_appends(&sheader, param_val);
				smart_str_appends(&sheader, "\"");

				efree(param_name);
				efree(param_val);
				prepend_comma = TRUE;
			}
		}
		smart_str_0(&sheader);
		curl_headers = curl_slist_append(curl_headers, sheader.c);
		curl_easy_setopt(curl, CURLOPT_URL, url);

		smart_str_free(&sheader);
	}

	/* the fetch method takes precedence so figure it out after we've added the OAuth params */

	if (0==strcmp(http_method, OAUTH_HTTP_METHOD_GET)) {
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	} else if (0==strcmp(http_method,OAUTH_HTTP_METHOD_POST)) {
		/* don't do anything if it's already a POST */
		if (strcmp(auth_type, OAUTH_AUTH_TYPE_FORM)) {
			/* filter oauth_ params */
			oauth_http_build_query(&post, ht, FALSE, PARAMS_FILTER_OAUTH);
			smart_str_0(&post);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post.c);
		}
	} else if (0==strcmp(http_method, OAUTH_HTTP_METHOD_PUT)) {
		curl_easy_setopt(curl, CURLOPT_PUT, 1L);
	} else if (0==strcmp(http_method, OAUTH_HTTP_METHOD_HEAD)) {
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	}

	/* Disable sending the 100 Expect header for POST requests */
	/* Other notes: if there is a redirect the POST becomes a GET request, see curl_easy_setopt(3) and the CURLOPT_POSTREDIR option for more information */
	curl_headers = curl_slist_append(curl_headers, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, soo_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, soo);
	if(!sslcheck) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
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
	cres = curl_easy_perform(curl);
	if(surl.c) {
		smart_str_free(&surl);
	}
	if (post.c) {
		smart_str_free(&post);
	}
	smart_str_0(&soo->lastresponse);

	if (curl_headers) {
		curl_slist_free_all(curl_headers);
	}

	if (CURLE_OK == cres) {
		ctres = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (CURLE_OK == crres && ctres == CURLE_OK) {
			is_redirect = (response_code > 300 && response_code < 304 && soo->last_location_header);
			if(is_redirect && follow_redirects) {
				if(soo->redirects >= OAUTH_MAX_REDIRS) {
					cres = FAILURE;
					spprintf(&bufz, 0, "max redirections exceeded (max: %ld last redirect url: %s)", OAUTH_MAX_REDIRS, soo->last_location_header);
					MAKE_STD_ZVAL(zret);
					ZVAL_STRING(zret, soo->lastresponse.c, 1)
						so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);
					soo_handle_error(response_code, bufz, soo->lastresponse.c TSRMLS_CC);
					efree(bufz);
				} else {
					++soo->redirects;
					make_standard_query(ht, soo TSRMLS_CC);
					/* http_method for redirects should be GET */
					oauth_add_signature(soo, OAUTH_HTTP_METHOD_GET, soo->last_location_header, ht, NULL TSRMLS_CC);
					cres = make_req(soo, soo->last_location_header, ht, http_method, request_headers TSRMLS_CC);
				}
			} else {
				ALLOC_INIT_ZVAL(info);
				array_init(info);

				CAAL("http_code", response_code);

				if(is_redirect) {
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

				if(response_code == 200) {
					soo->redirects = 0;
				}

				/* XXX maybe we should instead check for specific codes, like 40X */
				if (response_code < 200 || response_code > 206) {
					cres = FAILURE;
					spprintf(&bufz, 0, "Invalid auth/bad request (got a %d, expected HTTP/1.1 20X or a redirect)", (int)response_code);
					MAKE_STD_ZVAL(zret);
					if(soo->lastresponse.c) {
						ZVAL_STRING(zret, soo->lastresponse.c, 1)
					} else {
						ZVAL_STRING(zret, "", 1)
					}
					so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);
					soo_handle_error(response_code, bufz, soo->lastresponse.c TSRMLS_CC);
					efree(bufz);
				}
			}
		}
	} else {
		spprintf(&bufz, 0, "making the request failed (%s)", curl_easy_strerror(cres));
		soo_handle_error(-1, bufz, soo->lastresponse.c TSRMLS_CC);
		efree(bufz);
	}
	curl_easy_cleanup(curl);
	return cres;
}
/* }}} */

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

static const char *oauth_get_http_method(php_so_object *soo, const char *http_method TSRMLS_DC)
{
	char *auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));

	if (0==strcmp(auth_type, OAUTH_AUTH_TYPE_FORM)) {
		return OAUTH_HTTP_METHOD_POST;
	} else if (!http_method) {
		return OAUTH_HTTP_METHOD_GET;
	}
	return http_method;
}

static int oauth_add_signature(php_so_object *soo, const char *http_method, char *uri, HashTable *args, HashTable *extra_args TSRMLS_DC) /* {{{ */
{
	char *sbs = NULL, *sig = NULL;
	zval **token_secret = NULL, **consumer_secret = NULL;

	sbs = oauth_generate_sig_base(soo, http_method, uri, args, extra_args TSRMLS_CC);
	if(!sbs) {
		return FAILURE;
	}

	consumer_secret = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
	SEPARATE_ZVAL(consumer_secret);
	token_secret = soo_get_property(soo, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);

	sig = soo_hmac_sha1(sbs, *consumer_secret, *token_secret TSRMLS_CC);
	efree(sbs);
	if(!sig) {
		return FAILURE;
	}

	SO_ADD_SIG(args, sig);

	return SUCCESS;
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

/* {{{ proto string getSBS(string http_method, string uri, array parameters)
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

	memset(soo->last_location_header, 0, OAUTH_MAX_HEADER_LEN);
	soo->redirects = 0;

	TSRMLS_SET_CTX(soo->thread_ctx);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|ss", &ck, &ck_len, &cs, &cs_len, &sig_method, &sig_method_len, &auth_method, &auth_method_len) == FAILURE) {
		return;
	}

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

/* {{{ proto void OAuth::__destruct()
   clean up of OAuth object */
SO_METHOD(__destruct)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	oauth_prop_hash_dtor(soo TSRMLS_CC);
}

/* {{{ proto array OAuth::getRequestToken(string request_token_url)
   Get request token */
SO_METHOD(getRequestToken)
{
	php_so_object *soo;
	zval **cs = NULL, *zret = NULL;
	char *url, *sbs, *sig = NULL;
	int url_len;
	HashTable *args;
	CURLcode retcode;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &url, &url_len) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid access token url length", NULL TSRMLS_CC);
		RETURN_FALSE;
	}
	ALLOC_HASHTABLE(args);
	zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);

	make_standard_query(args, soo TSRMLS_CC);
	sbs = oauth_generate_sig_base(soo, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), url, args, NULL TSRMLS_CC);
	if (!sbs) {
		FREE_ARGS_HASH(args);
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid url, unable to generate signature base string", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	cs = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
	sig = soo_hmac_sha1(sbs, *cs, NULL TSRMLS_CC);
	efree(sbs);

	if (!sig) {
		FREE_ARGS_HASH(args);
		RETURN_NULL();
	}

	SO_ADD_SIG(args, sig);

	retcode = make_req(soo, url, args, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), NULL TSRMLS_CC);
	FREE_ARGS_HASH(args);

	if (retcode == CURLE_OK && soo->lastresponse.c) {
		array_init(return_value);
		MAKE_STD_ZVAL(zret);
		ZVAL_STRINGL(zret, soo->lastresponse.c, soo->lastresponse.len, 1);
		so_set_response_args(soo->properties, zret, return_value TSRMLS_CC);
		return;
	}
	RETURN_NULL();
}
/* }}} */

/* {{{ proto bool OAuth::enableRedirects()
   Follow and sign redirects automatically (enabled by default) */
SO_METHOD(enableRedirects)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	soo->follow_redirects = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableRedirects()
   Don't follow redirects automatically, thus allowing the request to be manually redirected (enabled by default) */
SO_METHOD(disableRedirects)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	soo->follow_redirects = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableDebug()
   Disable debug mode */
SO_METHOD(disableDebug)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	soo->debug = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableDebug()
   Enable debug mode, will verbosely output http information about requests */
SO_METHOD(enableDebug)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	soo->debug = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableSSLChecks()
   Enable SSL verification for requests, enabled by default */
SO_METHOD(enableSSLChecks)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	soo->sslcheck = 1;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableSSLChecks()
   Disable SSL verification for requests (be careful using this for production) */
SO_METHOD(disableSSLChecks)
{
	php_so_object *soo;

	soo = fetch_so_object(getThis() TSRMLS_CC);

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

/* {{{ proto bool OAuth::fetch(string protected_resource_url [, string|array extra_parameters, string request_type, array request_headers])
   fetch a protected resource, pass in extra_parameters (array(name => value) or "custom body") */
SO_METHOD(fetch)
{
	php_so_object *soo;
	int fetchurl_len, http_method_len = 0;
	char *fetchurl, *req_cur_key = NULL, *sbs = NULL, *sig = NULL, *auth_type;
	const char *final_http_method;
	zval **token = NULL, *zret = NULL, **cs, *request_args = NULL, *request_headers = NULL;
	zval *ts = NULL, **token_secret = NULL;
	void *p_current_req_val;
	uint req_cur_key_len;
	ulong req_num_key;
	char *http_method = NULL;
	HashTable *args = NULL, *rargs = NULL, *rheaders = NULL;
	CURLcode retcode;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zsa", &fetchurl, &fetchurl_len, &request_args, &http_method, &http_method_len, &request_headers) == FAILURE) {
		return;
	}


	if (fetchurl_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url length", NULL TSRMLS_CC);
		RETURN_NULL();
	}

	auth_type = Z_STRVAL_PP(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));

	if(!http_method_len) {
		final_http_method = oauth_get_http_method(soo, http_method TSRMLS_CC);
	} else {
		final_http_method = (const char *)http_method;
	}
	if(!strcasecmp(auth_type, OAUTH_AUTH_TYPE_FORM) && strcasecmp(final_http_method, OAUTH_HTTP_METHOD_POST)) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "auth type is set to HTTP POST with a non-POST http method, use setAuthType to put OAuth parameters somewhere else in the request", NULL TSRMLS_CC);
	}

	ALLOC_HASHTABLE(args);
	zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);

	make_standard_query(args, soo TSRMLS_CC);
	if (request_args) {
		rargs = HASH_OF(request_args);
	}

	if (request_headers) {
		rheaders = HASH_OF(request_headers);
	}

	token = soo_get_property(soo, OAUTH_ATTR_TOKEN TSRMLS_CC);
	if (token) {
		add_arg_for_req(args, OAUTH_PARAM_TOKEN, Z_STRVAL_PP(token) TSRMLS_CC);
	}

	sbs = oauth_generate_sig_base(soo, final_http_method, fetchurl, args, rargs TSRMLS_CC);
	if (!sbs) {
		FREE_ARGS_HASH(args);
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url, unable to generate signature base string", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	cs = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
	SEPARATE_ZVAL(cs);

	token_secret = soo_get_property(soo, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
	if (token_secret && Z_STRLEN_PP(token_secret) > 0) {
		ts = *token_secret;
	}

	sig = soo_hmac_sha1(sbs, *cs, ts TSRMLS_CC);
	efree(sbs);
	if (!sig) {
		FREE_ARGS_HASH(args);
		RETURN_NULL();
	}

	SO_ADD_SIG(args, sig);
	if (rargs) {
		for (zend_hash_internal_pointer_reset(rargs);
				zend_hash_get_current_key_ex(rargs, &req_cur_key, &req_cur_key_len, &req_num_key, 0, NULL) != HASH_KEY_NON_EXISTANT;
				zend_hash_move_forward(rargs)) {
			zend_hash_get_current_data(rargs, (void **)&p_current_req_val);
			add_arg_for_req(args, req_cur_key, Z_STRVAL_PP((zval **)p_current_req_val) TSRMLS_CC);
		}
	}
	retcode = make_req(soo, fetchurl, args, final_http_method, rheaders TSRMLS_CC);

	MAKE_STD_ZVAL(zret);
	ZVAL_STRINGL(zret, soo->lastresponse.c, soo->lastresponse.len, 1);
	so_set_response_args(soo->properties, zret, NULL TSRMLS_CC);

	FREE_ARGS_HASH(args);

	if (retcode == FAILURE || soo->lastresponse.c == NULL) {
		RETURN_NULL();
	}

	RETURN_BOOL(retcode == CURLE_OK && soo->lastresponse.c);
}
/* }}} */

/* {{{ proto array OAuth::getAccessToken(string access_token_url [, string auth_session_handle ])
   Get access token, if the server supports Scalable OAuth pass in the auth_session_handle to refresh the token (http://wiki.oauth.net/ScalableOAuth) */
SO_METHOD(getAccessToken)
{
	php_so_object *soo;
	int aturi_len = 0, ash_len = 0;
	char *aturi, *ash, *sbs, *sig = NULL;
	zval **cs = NULL, **token_secret, *ts = NULL, **token = NULL;
	zval *zret = NULL;
	HashTable *args;
	CURLcode retcode;

	soo = fetch_so_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &aturi, &aturi_len, &ash, &ash_len) == FAILURE) {
		return;
	}

	if (aturi_len < 1) {
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid access token url length", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	ALLOC_HASHTABLE(args);
	zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
	make_standard_query(args, soo TSRMLS_CC);

	if (ash_len > 0) {
		add_arg_for_req(args, OAUTH_PARAM_ASH, ash TSRMLS_CC);
	}

	token = soo_get_property(soo, OAUTH_ATTR_TOKEN TSRMLS_CC);
	if (token) {
		add_arg_for_req(args, OAUTH_PARAM_TOKEN, Z_STRVAL_PP(token) TSRMLS_CC);
	}

	sbs = oauth_generate_sig_base(soo, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), aturi, args, NULL TSRMLS_CC);
	if (!sbs) {
		FREE_ARGS_HASH(args);
		soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Unable to generate signature base string, perhaps the access token url is invalid", NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	cs = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
	SEPARATE_ZVAL(cs);

	token_secret = soo_get_property(soo, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
	if (token_secret && Z_STRLEN_PP(token_secret) > 0) {
		ts = *token_secret;
	}

	sig = soo_hmac_sha1(sbs, *cs, ts TSRMLS_CC);
	efree(sbs);
	if (!sig) {
		FREE_ARGS_HASH(args);
		RETURN_NULL();
	}

	SO_ADD_SIG(args, sig);

	retcode = make_req(soo, aturi, args, oauth_get_http_method(soo, OAUTH_HTTP_METHOD_GET TSRMLS_CC), NULL TSRMLS_CC);
	FREE_ARGS_HASH(args);

	if (retcode == CURLE_OK && soo->lastresponse.c) {
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
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setnonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
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
	SO_ME(__destruct,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */

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
	so_class_entry = zend_register_internal_class(&soce TSRMLS_CC);
	memcpy(&so_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

	INIT_CLASS_ENTRY(soo_ex_ce, "OAuthException", NULL);
	OAUTH(soo_exception_ce) = zend_register_internal_class_ex(&soo_ex_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	zend_declare_property_null(OAUTH(soo_exception_ce), "lastResponse", sizeof("lastResponse")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

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
	so_class_entry = NULL;
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
	PHP_MODULE_GLOBALS(oauth),
	PHP_GINIT(oauth),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

/**
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4 noexpandtab
 */

/*
+----------------------------------------------------------------------+
| See LICENSE file for further copyright information                   |
+----------------------------------------------------------------------+
| Authors: John Jawed <jawed@php.net>                                  |
|          Felipe Pena <felipe@php.net>                                |
|          Rasmus Lerdorf <rasmus@php.net>                             |
|          Tjerk Meesters <datibbaw@php.net>                           |
+----------------------------------------------------------------------+
*/

/* $Id$ */

#include "php_oauth.h"
#include "provider.h"
#include "ext/standard/php_array.h"

zend_class_entry *oauth_class_entry;
zend_class_entry *oauth_exception_class_entry;

zend_object_handlers oauth_object_handlers;

static zend_object *oauth_object_clone(zval *this_ptr TSRMLS_DC);
static zend_object *oauth_object_new(zend_class_entry *ce TSRMLS_DC);

#if 0
static zend_object *php_so_register_object(php_so_object *soo TSRMLS_DC);
#endif

static zend_object *oauth_object_clone(zval *zobject TSRMLS_DC) /* {{{ */
{
	zend_object *old_object;
	zend_object *new_object;

	old_object = Z_OBJ_P(zobject);
	new_object = oauth_object_new(old_object->ce TSRMLS_CC);

	zend_objects_clone_members(new_object, old_object TSRMLS_CC);

	return new_object;
}
/* }}} */

static int oauth_parse_str(char *params, zval *dest_array TSRMLS_DC) /* {{{ */
{
	char *kvpair, *key, *value, *separator = NULL;
	char *strtok_buf = NULL;
	int key_len;

	if (!params) {
		return FAILURE;
	}

	separator = (char *) estrdup(PG(arg_separator).input);
	kvpair = php_strtok_r(params, separator, &strtok_buf);
	while (kvpair) {
		key = kvpair;
		value = strchr(kvpair, '=');

		if (value) { /* have a value */
			int value_len;

			key_len = value - kvpair;
			*value++ = '\0';

			php_url_decode(key, key_len);
			value_len = php_url_decode(value, strlen(value));
			value = estrndup(value, value_len);
		} else {
			php_url_decode(key, key_len);
			value = estrndup("", sizeof("") - 1);
		}
		add_assoc_string(dest_array, key, value);
		efree(value);
		kvpair = php_strtok_r(NULL, separator, &strtok_buf);
	}

	efree(separator);
	return SUCCESS;
}
/* }}} */

static int so_set_response_args(HashTable *hasht, zval *data, zval *retarray TSRMLS_DC) /* {{{ */
{
	if (data && Z_TYPE_P(data) == IS_STRING) {
		if (retarray) {
			char *res = NULL;

			res = estrndup(Z_STRVAL_P(data), Z_STRLEN_P(data));
			/* do not use oauth_parse_str here, we want the result to pass through input filters */
			sapi_module.treat_data(PARSE_STRING, res, retarray TSRMLS_CC);
		}

		if (zend_hash_str_update(hasht, OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES), data) != NULL) {
			return SUCCESS;
		}
	}
	return FAILURE;
}
/* }}} */

static zval *so_set_response_info(HashTable *hasht, zval *info) /* {{{ */
{
	return zend_hash_str_update(hasht, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO), info);
}
/* }}} */

static zend_object* oauth_object_new(zend_class_entry *class_type TSRMLS_DC) /* {{{ */
{
	php_so_object *intern = ecalloc(1, sizeof(php_so_object) + sizeof(zval) * (class_type->default_properties_count - 1));

	intern->signature = NULL;
	intern->nonce = NULL;
	intern->timestamp = NULL;
	intern->sig_ctx = NULL;

	intern->timeout = 0;
	intern->properties = NULL;

	intern->headers_in.s = NULL;
	intern->lastresponse.s = NULL;

	memset(intern->last_location_header, 0, OAUTH_MAX_HEADER_LEN);

	intern->redirects = 0;
	intern->debug = 0;
	intern->sslcheck = OAUTH_SSLCHECK_BOTH;
	intern->follow_redirects = 1;

	intern->debug_info = emalloc(sizeof(php_so_debug));
	INIT_DEBUG_INFO(intern->debug_info);

	array_init(&intern->debugArr);

	intern->zo.handlers = &oauth_object_handlers;

	zend_object_std_init(&intern->zo, class_type TSRMLS_CC);
	object_properties_init(&intern->zo, class_type);

#if OAUTH_USE_CURL
	intern->reqengine = OAUTH_REQENGINE_CURL;
#else
	intern->reqengine = OAUTH_REQENGINE_STREAMS;
#endif

	return &intern->zo;
}
/* }}} */

void oauth_object_free_storage(zend_object *object TSRMLS_DC)
{
	php_so_object *intern = php_oauth_obj_from_obj(object);

	zend_object_std_dtor(&intern->zo TSRMLS_CC);

	FREE_ARGS_HASH(intern->properties);
	intern->properties = NULL;

	if (intern->debug_info) {
		FREE_DEBUG_INFO(intern->debug_info);
		efree(intern->debug_info);
		intern->debug_info = NULL;
	}

	smart_str_free(&intern->headers_in);

	if (intern->headers_out.s) {
		smart_str_free(&intern->headers_out);
	}

	zval_ptr_dtor(&intern->debugArr);

	OAUTH_SIGCTX_FREE(intern->sig_ctx);
	if (intern->nonce) {
		efree(intern->nonce);
	}

	if (intern->timestamp) {
		efree(intern->timestamp);
	}

	if (intern->signature) {
		STR_FREE(intern->signature);
	}
}

static zend_object *new_so_object(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	return oauth_object_new(ce TSRMLS_CC);
}
/* }}} */

void soo_handle_error(php_so_object *soo, long errorCode, char *msg, char *response, char *additional_info TSRMLS_DC) /* {{{ */
{
	zend_throw_exception(oauth_exception_class_entry, msg, errorCode TSRMLS_CC);
#if 0
//	MAKE_STD_ZVAL(ex);
	object_init_ex(ex, soox);

	if (!errorCode) {
		php_error(E_WARNING, "caller did not pass an errorcode!");
	} else {
		zend_update_property_long(dex, ex, "code", sizeof("code")-1, errorCode TSRMLS_CC);
	}
	if (response) {
		zend_update_property_string(dex, ex, "lastResponse", sizeof("lastResponse")-1, response TSRMLS_CC);
	}
	if(soo && soo->debug && soo->debugArr) {
		zend_update_property(dex, ex, "debugInfo", sizeof("debugInfo") - 1, soo->debugArr TSRMLS_CC);
	}

	if(additional_info) {
		zend_update_property_string(dex, ex, "additionalInfo", sizeof("additionalInfo")-1, additional_info TSRMLS_CC);
	}
	
	zend_update_property_string(dex, ex, "message", sizeof("message")-1, msg TSRMLS_CC);
	zend_throw_exception_object(ex TSRMLS_CC);
#endif
}
/* }}} */

static zend_string *soo_sign_hmac(php_so_object *soo, char *message, const char *cs, const char *ts, const oauth_sig_context *ctx TSRMLS_DC) /* {{{ */
{
	zval args[4], retval, func;
	char *tret;
	int ret;
	zend_string *result;

	ZVAL_STRING(&func, "hash_hmac");

	if (!zend_is_callable(&func, 0, NULL OAUTH_IS_CALLABLE_CC)) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "HMAC signature generation failed, is ext/hash installed?", NULL, NULL TSRMLS_CC);
		zval_ptr_dtor(&func);
		return NULL;
	}

	/* cs and ts would at best be empty, so this should be safe ;-) */
	zend_spprintf(&tret, 0, "%s&%s", cs, ts);

	ZVAL_UNDEF(&retval);
	ZVAL_STRING(&args[0], ctx->hash_algo);
	ZVAL_STRING(&args[1], message);
	ZVAL_STRING(&args[2], tret);
	ZVAL_TRUE(&args[3]);

	ret = call_user_function(EG(function_table), NULL, &func, &retval, 4, args TSRMLS_CC);
	result = php_base64_encode((unsigned char *)Z_STRVAL(retval), Z_STRLEN(retval));

	efree(tret);
	zval_ptr_dtor(&retval);
	zval_ptr_dtor(&args[3]);
	zval_ptr_dtor(&args[2]);
	zval_ptr_dtor(&args[1]);
	zval_ptr_dtor(&args[0]);
	
	zval_ptr_dtor(&func);

	return result;
}
/* }}} */

static zend_string *soo_sign_rsa(php_so_object *soo, char *message, const oauth_sig_context *ctx TSRMLS_DC)
{
	zval args[3], func, retval;
	zend_string *result;

	/* check for empty private key */
	if (Z_TYPE(ctx->privatekey) != IS_RESOURCE) {
		return NULL;
	}

	ZVAL_STRING(&func, "openssl_sign");
	ZVAL_UNDEF(&retval);
	ZVAL_STRING(&args[0], message);
	ZVAL_EMPTY_STRING(&args[1]);

	/* TODO: add support for other algorithms instead of OPENSSL_ALGO_SHA1 */
	/* args[1] is filled by function */
	args[2] = ctx->privatekey;

	if (call_user_function(EG(function_table), NULL, &func, &retval, 3, args TSRMLS_CC) == SUCCESS && Z_TYPE(retval) == IS_TRUE) {
		result = php_base64_encode((unsigned char *)Z_STRVAL(args[1]), Z_STRLEN(args[1]));
		zval_ptr_dtor(&args[1]);
	} else {
		result = NULL;
	}

	zval_ptr_dtor(&retval);
	zval_ptr_dtor(&func);
	zval_ptr_dtor(&args[0]);

	return result;
}
/* }}} */

static zend_string *soo_sign_plain(php_so_object *soo, const char *cs, const char *ts TSRMLS_DC) /* {{{ */
{
	zend_string *result;
	char *str;
	int len;

	len = zend_spprintf(&str, 0, "%s&%s", cs, ts);

	result = STR_INIT(str, len, 0);
	efree(str);

	return result;
}
/* }}} */

oauth_sig_context *oauth_create_sig_context(const char *sigmethod)
{
	oauth_sig_context *ctx;

	OAUTH_SIGCTX_INIT(ctx);
	if (0==strcmp(sigmethod, OAUTH_SIG_METHOD_HMACSHA1)) {
		OAUTH_SIGCTX_HMAC(ctx, "sha1");
	} else if (0==strcmp(sigmethod, OAUTH_SIG_METHOD_HMACSHA256)) {
		OAUTH_SIGCTX_HMAC(ctx, "sha256");
	} else if (0==strcmp(sigmethod, OAUTH_SIG_METHOD_RSASHA1)) {
		OAUTH_SIGCTX_RSA(ctx, "sha1");
	} else if (0==strcmp(sigmethod, OAUTH_SIG_METHOD_PLAINTEXT)) {
		OAUTH_SIGCTX_PLAIN(ctx);
	}

	return ctx;
}

zend_string *soo_sign(php_so_object *soo, char *message, zval *cs, zval *ts, const oauth_sig_context *ctx TSRMLS_DC)
{
	const char *csec = cs?Z_STRVAL_P(cs):"", *tsec = ts ? Z_STRVAL_P(ts) : "";

	if (OAUTH_SIGCTX_TYPE_HMAC==ctx->type) {
		return soo_sign_hmac(soo, message, csec, tsec, ctx TSRMLS_CC);
	} else if (OAUTH_SIGCTX_TYPE_RSA==ctx->type) {
		return soo_sign_rsa(soo, message, ctx TSRMLS_CC);
	} else if(OAUTH_SIGCTX_TYPE_PLAIN==ctx->type) {
		return soo_sign_plain(soo, csec, tsec TSRMLS_CC);
	}
	return NULL;
}

static inline zval *soo_get_property(php_so_object *soo, char *prop_name) /* {{{ */
{
	return zend_hash_str_find(soo->properties, prop_name, strlen(prop_name) + 1);
}
/* }}} */

/* XXX for auth type, need to make sure that the auth type is actually supported before setting */
static inline int soo_set_property(php_so_object *soo, zval *prop, char *prop_name TSRMLS_DC) /* {{{ */
{
	return zend_hash_str_update(soo->properties, prop_name, strlen(prop_name) + 1, prop) ? SUCCESS : FAILURE;
}
/* }}} */

zend_string *oauth_url_encode(char *url, int url_len) /* {{{ */
{
	zend_string *urlencoded = NULL, *result;

	if (url) {
		if (url_len < 0) {
			url_len = strlen(url);
		}
		urlencoded = php_raw_url_encode(url, url_len);
	}

	if (urlencoded) {
		result = php_str_to_str_ex(urlencoded->val, urlencoded->len, "%7E", sizeof("%7E")-1, "~", sizeof("~")-1, 0, NULL);
		STR_FREE(urlencoded);
		return result;
	}
	return NULL;
}
/* }}} */

zend_string* oauth_http_encode_value(zval *v TSRMLS_DC)
{
	zend_string *param_value = NULL;

	switch (Z_TYPE_P(v)) {
		case IS_STRING:
			param_value = oauth_url_encode(Z_STRVAL_P(v), Z_STRLEN_P(v));
			break;

		default:
			SEPARATE_ZVAL(v);
			convert_to_string_ex(v);
			param_value = oauth_url_encode(Z_STRVAL_P(v), Z_STRLEN_P(v));
	}

	return param_value;
}

static int oauth_strcmp(zval *first, zval *second TSRMLS_DC)
{
	zval result;

	if (FAILURE==string_compare_function(&result, first, second TSRMLS_CC)) {
		return 0;
	}

	if (Z_LVAL(result) < 0) {
		return -1;
	} else if (Z_LVAL(result) > 0) {
		return 1;
	}

	return 0;
}

static int oauth_compare_value(const void *a, const void *b TSRMLS_DC)
{
	Bucket *f, *s;
	zval *first, *second;

	f = (Bucket *)a;
	s = (Bucket *)b;

	first = &f->val;
	second = &f->val;

	return oauth_strcmp(first, second TSRMLS_CC);
}

static int oauth_compare_key(const void *a, const void *b TSRMLS_DC)
{
	Bucket *f, *s;
	zval first, second;

	f = (Bucket *)a;
	s = (Bucket *)b;

    if (f->key == NULL) {
		ZVAL_LONG(&first, f->h);
	} else {
		ZVAL_STR(&first, f->key);
	}

	if (s->key == NULL) {
		ZVAL_LONG(&second, s->h);
	} else {
		ZVAL_STR(&second, s->key);
	}

	return oauth_strcmp(&first, &second TSRMLS_CC);
}

/* build url-encoded string from args, optionally starting with & */ 
int oauth_http_build_query(php_so_object *soo, smart_str *s, HashTable *args, zend_bool prepend_amp TSRMLS_DC)
{
	zval *cur_val;
	zend_string *arg_key = NULL;
	zend_string *param_value;
	zend_string *cur_key;
	int numargs = 0, hash_key_type, skip_append = 0, i, found;
	ulong num_index;
	HashPosition pos;
	smart_str keyname = {0};

	smart_str_0(s);
	if (args) {
		if (soo && !soo->is_multipart) {
			for (zend_hash_internal_pointer_reset_ex(args, &pos);
				 (hash_key_type = zend_hash_get_current_key_ex(args, &cur_key, &num_index, 0, &pos)) != HASH_KEY_NON_EXISTENT;
				 zend_hash_move_forward_ex(args, &pos)) {
				cur_val = zend_hash_get_current_data_ex(args, &pos);
				if (hash_key_type == HASH_KEY_IS_STRING && Z_STRVAL_P(cur_val)[0] == '@' && Z_STRVAL_P(cur_val)[0] =='@') {
					soo->is_multipart = 1;
					break;
				}
			}
		}

		for (zend_hash_internal_pointer_reset_ex(args, &pos);
				(hash_key_type = zend_hash_get_current_key_ex(args, &cur_key, &num_index, 0, &pos)) != HASH_KEY_NON_EXISTENT;
				zend_hash_move_forward_ex(args, &pos)) {
			cur_val = zend_hash_get_current_data_ex(args, &pos);

			skip_append = 0;

			switch (hash_key_type) {
				case HASH_KEY_IS_STRING:
					if (soo && soo->is_multipart && strncmp(cur_key->val, "oauth_", 6) != 0) {
						found = 0;
						for (i=0; i<soo->multipart_files_num; ++i) {
							if (0 == strncmp(soo->multipart_params[i], cur_key->val, cur_key->len + 1)) {
								found = 1;
								break;
							}
						}
						
						if (found) {
							continue;
						}
						
						soo->multipart_files = erealloc(soo->multipart_files, sizeof(char *) * (soo->multipart_files_num + 1));
						soo->multipart_params = erealloc(soo->multipart_params, sizeof(char *) * (soo->multipart_files_num + 1));
						
						convert_to_string_ex(cur_val);
						soo->multipart_files[soo->multipart_files_num] = Z_STRVAL_P(cur_val);
						soo->multipart_params[soo->multipart_files_num] = cur_key->val;

						++soo->multipart_files_num;
						/* we don't add multipart files to the params */
						skip_append = 1;
					} else {
						arg_key = oauth_url_encode(cur_key->val, cur_key->len);
					}
					break;

				case HASH_KEY_IS_LONG:
					/* take value of num_index instead */
					arg_key = NULL;
					break;

				default:
					continue;
			}

			if (skip_append) {
				continue;
			}

			if (arg_key) {
				smart_str_appendl(&keyname, arg_key->val, arg_key->len);
				STR_FREE(arg_key);
			} else {
				smart_str_append_unsigned(&keyname, num_index);
			}

			if (IS_ARRAY==Z_TYPE_P(cur_val)) {
				HashPosition val_pos;
				zval *val_cur_val;

				/* make shallow copy */
				SEPARATE_ZVAL(cur_val);
				/* sort array based on string comparison */
				zend_hash_sort(Z_ARRVAL_P(cur_val), zend_qsort, oauth_compare_value, 1 TSRMLS_CC);

				/* traverse array */
				zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(cur_val), &val_pos);
				while ((val_cur_val = zend_hash_get_current_data_ex(Z_ARRVAL_P(cur_val), &val_pos)) != NULL) {
					if (prepend_amp) {
						smart_str_appendc(s, '&');
					}

					smart_str_append(s, &keyname);
					param_value = oauth_http_encode_value(val_cur_val TSRMLS_CC);
					if (param_value) {
						smart_str_appendc(s, '=');
						smart_str_appendl(s, param_value->val, param_value->len);
						STR_FREE(param_value);
					}
					prepend_amp = TRUE;
					++numargs;
					zend_hash_move_forward_ex(Z_ARRVAL_P(cur_val), &val_pos);
				}
				/* clean up */
			} else {
				if (prepend_amp) {
					smart_str_appendc(s, '&');
				}
				smart_str_append(s, &keyname);
				param_value = oauth_http_encode_value(cur_val TSRMLS_CC);
				if (param_value) {
					smart_str_appendc(s, '=');
					smart_str_appendl(s, param_value->val, param_value->len);
					STR_FREE(param_value);
				}
				prepend_amp = TRUE;
				++numargs;
			}
			smart_str_free(&keyname);

			smart_str_0(s);
		}
	}
	return numargs;
}

static zval *get_request_var(int source, char *name TSRMLS_DC)
{
	return zend_hash_str_find(Z_ARRVAL(PG(http_globals)[source]), name, strlen(name) + 1);
}

/* retrieves parameter value from the _GET or _POST superglobal */
void get_request_param(char *arg_name, char **return_val, int *return_len TSRMLS_DC)
{
	zval *param;

	if ((param = get_request_var(TRACK_VARS_GET, arg_name TSRMLS_CC)) == NULL) {
		param = get_request_var(TRACK_VARS_POST, arg_name TSRMLS_CC);
	}

	if (Z_TYPE_P(param) == IS_STRING) {
		*return_val = Z_STRVAL_P(param);
		*return_len = Z_STRLEN_P(param);
	} else {
		*return_val = NULL;
		*return_len = 0;
	}
}

/*
 * This function does not currently care to respect parameter precedence, in the sense that if a common param is defined
 * in POST/GET or Authorization header, the precendence is defined by: OAuth Core 1.0 section 9.1.1
 */

char *oauth_generate_sig_base(php_so_object *soo, const char *http_method, const char *uri, HashTable *post_args, HashTable *extra_args TSRMLS_DC) /* {{{ */
{
	zval params;
	char *query;
	char *s_port = NULL, *bufz = NULL;
	zend_string *sbs_query_part = NULL, *sbs_scheme_part = NULL;
	php_url *urlparts;
	smart_str sbuf = {0};

	urlparts = php_url_parse_ex(uri, strlen(uri));
	php_strtolower(urlparts->scheme, strlen(urlparts->scheme));
	php_strtolower(urlparts->host, strlen(urlparts->host));

	if (urlparts) {
		if (!urlparts->host || !urlparts->scheme) {
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid url when trying to build base signature string", NULL, NULL TSRMLS_CC);
			php_url_free(urlparts);
			return NULL;
		}
		smart_str_appends(&sbuf, urlparts->scheme);
		smart_str_appends(&sbuf, "://");
		smart_str_appends(&sbuf, urlparts->host);

		if (urlparts->port && ((!strcmp("http", urlparts->scheme) && OAUTH_HTTP_PORT != urlparts->port)
					|| (!strcmp("https", urlparts->scheme) && OAUTH_HTTPS_PORT != urlparts->port))) {
			zend_spprintf(&s_port, 0, "%d", urlparts->port);
			smart_str_appendc(&sbuf, ':');
			smart_str_appends(&sbuf, s_port);
			efree(s_port);
		}

		if (urlparts->path) {
			smart_str squery = {0};
			smart_str_appends(&sbuf, urlparts->path);
			smart_str_0(&sbuf);

			array_init(&params);

			/* merge order = oauth_args - extra_args - query */
			if (post_args) {
				zend_hash_merge(Z_ARRVAL(params), post_args, zval_add_ref, 1);
			}

			if (extra_args) {
				zend_hash_merge(Z_ARRVAL(params), extra_args, zval_add_ref, 1);
			}

			if (urlparts->query) {
				query = estrdup(urlparts->query);
				oauth_parse_str(query, &params TSRMLS_CC);
				efree(query);
			}

			/* remove oauth_signature if it's in the hash */
			zend_hash_str_del(Z_ARRVAL(params), OAUTH_PARAM_SIGNATURE, sizeof(OAUTH_PARAM_SIGNATURE) - 1);

			/* exret2 = uksort(&exargs2[0], "strnatcmp") */
			zend_hash_sort(Z_ARRVAL(params), zend_qsort, oauth_compare_key, 0 TSRMLS_CC);

			oauth_http_build_query(soo, &squery, Z_ARRVAL(params), FALSE TSRMLS_CC);
			smart_str_0(&squery);
			zval_ptr_dtor(&params);

			sbs_query_part = oauth_url_encode(squery.s ? squery.s->val : "", squery.s ? squery.s->len : 0);
			sbs_scheme_part = oauth_url_encode(sbuf.s->val, sbuf.s->len);

			zend_spprintf(&bufz, 0, "%s&%s&%s", http_method, sbs_scheme_part->val, sbs_query_part ? sbs_query_part->val : "");
			/* TODO move this into oauth_get_http_method()
			   soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL TSRMLS_CC);
			   */
			if(sbs_query_part) {
				STR_FREE(sbs_query_part);
			}
			if(sbs_scheme_part) {
				STR_FREE(sbs_scheme_part);
			}
			smart_str_free(&squery);
		} else {
			/* Bug 22630 - throw exception if no path given */
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid path (perhaps you only specified the hostname? try adding a slash at the end)", NULL, NULL TSRMLS_CC);
			return NULL;
		}

		smart_str_free(&sbuf);

		php_url_free(urlparts);

		if (soo && soo->debug && soo->debug_info) {
			if (soo->debug_info->sbs) {
				efree(soo->debug_info->sbs);
			}
			soo->debug_info->sbs = bufz ? estrdup(bufz) : NULL;
		}
		return bufz;
	}
	return NULL;
}
/* }}} */

static void oauth_set_debug_info(php_so_object *soo TSRMLS_DC) 
{
	char *tmp;

	if (soo->debug_info) {
		if(Z_TYPE(soo->debugArr) == IS_ARRAY) {
			zval_ptr_dtor(&soo->debugArr);
		}
		ZVAL_NEW_ARR(&soo->debugArr);

		if (soo->debug_info->sbs) {
			add_assoc_string(&soo->debugArr, "sbs", soo->debug_info->sbs);
		}

		ADD_DEBUG_INFO(&soo->debugArr, "headers_sent", soo->debug_info->headers_out, 1);
		ADD_DEBUG_INFO(&soo->debugArr, "headers_recv", soo->headers_in, 1);
		ADD_DEBUG_INFO(&soo->debugArr, "body_sent", soo->debug_info->body_out, 0);
		ADD_DEBUG_INFO(&soo->debugArr, "body_recv", soo->debug_info->body_in, 0);
		ADD_DEBUG_INFO(&soo->debugArr, "info", soo->debug_info->curl_info, 0);

		zend_update_property(oauth_class_entry, soo->this_ptr, "debugInfo", sizeof("debugInfo") - 1, &soo->debugArr TSRMLS_CC);
	} else {
		ZVAL_UNDEF(&soo->debugArr);
	}
}

static int add_arg_for_req(HashTable *ht, const char *arg, const char *val TSRMLS_DC) /* {{{ */
{
	zval tmp;

	ZVAL_STRING(&tmp, val);
	return zend_symtable_str_update(ht, arg, strlen(arg), &tmp) ? SUCCESS : FAILURE;
}
/* }}} */

void oauth_add_signature_header(HashTable *request_headers, HashTable *oauth_args, smart_str *header TSRMLS_DC)
{
	smart_str sheader = {0};
	zend_bool prepend_comma = FALSE;

	zval *curval;
	zend_string *param_name, *param_val, *cur_key;
	ulong num_key;

	smart_str_appends(&sheader, "OAuth ");

	for (zend_hash_internal_pointer_reset(oauth_args);
			(curval = zend_hash_get_current_data(oauth_args)) != NULL;
			zend_hash_move_forward(oauth_args)) {
		zend_hash_get_current_key_ex(oauth_args, &cur_key, &num_key, 0, NULL);

		if (prepend_comma) {
			smart_str_appendc(&sheader, ',');
		}
		param_name = oauth_url_encode(cur_key->val, cur_key->len);
		param_val = oauth_url_encode(Z_STRVAL_P(curval), Z_STRLEN_P(curval));

		smart_str_appendl(&sheader, param_name->val, param_name->len);
		smart_str_appendc(&sheader, '=');
		smart_str_appends(&sheader, "\"");
		smart_str_appendl(&sheader, param_val->val, param_val->len);
		smart_str_appends(&sheader, "\"");

		STR_FREE(param_name);
		STR_FREE(param_val);
		prepend_comma = TRUE;
	}
	smart_str_0(&sheader);

	if (!header) {
		add_arg_for_req(request_headers, "Authorization", sheader.s->val TSRMLS_CC);
	} else {
		smart_str_appendl(header, sheader.s->val, sheader.s->len);
	}
	smart_str_free(&sheader);
}

#define HTTP_RESPONSE_CAAS(zvalp, header, storkey) { \
	if (strncasecmp(Z_STRVAL_P(zvalp), header, sizeof(header) - 1) == 0) { \
		CAAS(storkey, (Z_STRVAL_P(zvalp) + sizeof(header) - 1)); \
	} \
}

#define HTTP_RESPONSE_CAAD(zvalp, header, storkey) { \
	if (0==strncasecmp(Z_STRVAL_P(zvalp), header, sizeof(header) - 1)) { \
		CAAD(storkey, strtoul(Z_STRVAL_P(zvalp) + sizeof(header) - 1, NULL, 10)); \
	} \
}

#define HTTP_RESPONSE_CODE(zvalp) \
	if (response_code < 0 && strncasecmp(Z_STRVAL_P(zvalp), "HTTP/", 5) == 0 && Z_STRLEN_P(zvalp) >= 12) { \
		response_code = strtol(Z_STRVAL_P(zvalp) + 9, NULL, 10); \
		CAAL("http_code", response_code); \
	}

#define HTTP_RESPONSE_LOCATION(zvalp) \
	if (strncasecmp(Z_STRVAL_P(zvalp), "Location: ", 10) == 0) { \
		strlcpy(soo->last_location_header, Z_STRVAL_P(zvalp)+10, OAUTH_MAX_HEADER_LEN); \
	}

static long make_req_streams(php_so_object *soo, const char *url, const smart_str *payload, const char *http_method, HashTable *request_headers TSRMLS_DC) /* {{{ */
{
	php_stream_context *sc;
	zval zpayload, zmethod, zredirects, zerrign;
	long response_code = -1;
	php_stream *s;
	int set_form_content_type = 0;
	php_netstream_data_t *sock;
	struct timeval tv;
	int secs = 0;

#ifdef ZEND_ENGINE_2_4
	sc = php_stream_context_alloc(TSRMLS_C);
#else
	sc = php_stream_context_alloc();
#endif

	if (payload->s->len) {
		smart_str_0(payload);
		ZVAL_STRINGL(&zpayload, payload->s->val, payload->s->len);
		php_stream_context_set_option(sc, "http", "content", &zpayload);
		/**
		 * remember to set application/x-www-form-urlencoded content-type later on
		 * lest the php streams guys come and beat you up
		*/
		set_form_content_type = 1;
	}

	if (request_headers) {
		zval *cur_val, zheaders;
		zend_string *cur_key;
		ulong num_key;
		smart_str sheaders = {0};
		int first = 1;

		for (zend_hash_internal_pointer_reset(request_headers);
				(cur_val = zend_hash_get_current_data(request_headers)) != NULL;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key and string value are used */
			smart_str sheaderline = {0};

			if (Z_TYPE_P(cur_val) != IS_STRING) {
				continue;
			}

			if (zend_hash_get_current_key_ex(request_headers, &cur_key, &num_key, 0, NULL) != HASH_KEY_IS_STRING) {
				continue;
			}

			smart_str_appendl(&sheaderline, cur_key->val, cur_key->len);

			if (strcasecmp(cur_key->val, "content-type") == 0) {
				set_form_content_type = 0;
			}
			smart_str_appends(&sheaderline, ": ");
			smart_str_appendl(&sheaderline, Z_STRVAL_P(cur_val), Z_STRLEN_P(cur_val));

			if (first) {
				first = 0;
			} else {
				smart_str_appends(&sheaders, "\r\n");
			}
			smart_str_append(&sheaders, &sheaderline);
			smart_str_free(&sheaderline);
		}

		if (set_form_content_type) {
			/* still need to add our own content-type? */
			if (!first) {
				smart_str_appends(&sheaders, "\r\n");
			}
			smart_str_appends(&sheaders, "Content-Type: application/x-www-form-urlencoded");
		}
		if (sheaders.s->len) {
			ZVAL_STR(&zheaders, sheaders.s);
			php_stream_context_set_option(sc, "http", "header", &zheaders);
			if (soo->debug) {
				smart_str_append(&soo->debug_info->headers_out, &sheaders);
			}
		}
		smart_str_free(&sheaders);
	}
	/* set method */
	ZVAL_STRING(&zmethod, (char*)http_method);
	php_stream_context_set_option(sc, "http", "method", &zmethod);
	/* set maximum redirects; who came up with the ridiculous logic of <= 1 means no redirects ?? */
	ZVAL_LONG(&zredirects, 1L);
	php_stream_context_set_option(sc, "http", "max_redirects", &zredirects);
	/* using special extension to treat redirects as regular document (requires patch in php) */
	ZVAL_TRUE(&zerrign);
	php_stream_context_set_option(sc, "http", "ignore_errors", &zerrign);

	smart_str_free(&soo->lastresponse);
	smart_str_free(&soo->headers_in);

	if ((s = php_stream_open_wrapper_ex((char*)url, "rb", REPORT_ERRORS | ENFORCE_SAFE_MODE, NULL, sc))) {
		zval info;
		zend_string *buf;

		ZVAL_NEW_ARR(&info);

		CAAS("url", url);

		if (Z_TYPE(s->wrapperdata) == IS_ARRAY) {
			zval *tmp;

			zend_hash_internal_pointer_reset(Z_ARRVAL(s->wrapperdata));
			while ((tmp = zend_hash_get_current_data(Z_ARRVAL(s->wrapperdata)))) {
				smart_str_appendl(&soo->headers_in, Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				smart_str_appends(&soo->headers_in, "\r\n");
				HTTP_RESPONSE_CODE(tmp);
				HTTP_RESPONSE_LOCATION(tmp);
				HTTP_RESPONSE_CAAS(tmp, "Content-Type: ", "content_type");
				HTTP_RESPONSE_CAAD(tmp, "Content-Length: ", "download_content_length");
				zend_hash_move_forward(Z_ARRVAL(s->wrapperdata));
			}
			if (HTTP_IS_REDIRECT(response_code) && soo->last_location_header) {
				CAAS("redirect_url", soo->last_location_header);
			}
		}

		if(soo->timeout) {
			sock = (php_netstream_data_t*)s->abstract;
			secs = soo->timeout / 1000;
			tv.tv_sec = secs;
			tv.tv_usec = ((soo->timeout - (secs * 1000)) * 1000) % 1000000;
			sock->timeout = tv;
		}

		if ((buf = php_stream_copy_to_mem(s, PHP_STREAM_COPY_ALL, 0)) != NULL) {
			smart_str_appendl(&soo->lastresponse, buf->val, buf->len);
			CAAD("size_download", buf->len);
			STR_FREE(buf);
		} else {
			CAAD("size_download", 0);
		}
		smart_str_0(&soo->lastresponse);
		smart_str_0(&soo->headers_in);

		CAAD("size_upload", payload->s->len);

		so_set_response_info(soo->properties, &info);

		php_stream_close(s);
	} else {
		char *bufz;

		zend_spprintf(&bufz, 0, "making the request failed (%s)", "dunno why");
		soo_handle_error(soo, -1, bufz, soo->lastresponse.s->val, NULL TSRMLS_CC);
		efree(bufz);
	}

	if(soo->debug) {
		smart_str_append(&soo->debug_info->body_in, &soo->lastresponse);
		smart_str_append(&soo->debug_info->body_out, payload);
	}

	return response_code;
}
/* }}} */

#if OAUTH_USE_CURL
static size_t soo_read_response(char *ptr, size_t size, size_t nmemb, void *ctx) /* {{{ */
{
	uint relsize;
	php_so_object *soo = (php_so_object *)ctx;

	relsize = size * nmemb;
	smart_str_appendl(&soo->lastresponse, ptr, relsize);

	return relsize;
}
/* }}} */

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
	size_t hlen, vpos = sizeof("Location:") - 1;
	php_so_object *soo;

	header = (char *)ptr;
	hlen = nmemb * size;
	soo = (php_so_object *)ctx;

	/* handle Location header */
	if (hlen > vpos && 0==strncasecmp(header, "Location:", vpos)) {
		size_t eol = hlen;
		/* find value start */
		while (vpos != eol && ' '==header[vpos]) {
			++vpos;
		}
		/* POST: vpos == eol OR vpos < eol => value start found */
		while (vpos != eol && strchr("\r\n\0", header[eol - 1])) {
			--eol;
		}
		/* POST: vpos == eol OR vpos < eol => value end found */
		if (vpos != eol) {
			if (eol - vpos >= OAUTH_MAX_HEADER_LEN) {
				eol = vpos + OAUTH_MAX_HEADER_LEN - 1;
			}
			/* POST: eol - vpos <= OAUTH_MAX_HEADER_LEN */
			strncpy(soo->last_location_header, header + vpos, eol - vpos);
		}
		soo->last_location_header[eol - vpos] = '\0';
	}
	if(strncasecmp(header, "\r\n", 2)) {
		smart_str_appendl(&soo->headers_in, header, hlen);
	}
	return hlen;
}

long make_req_curl(php_so_object *soo, const char *url, const smart_str *payload, const char *http_method, HashTable *request_headers TSRMLS_DC) /* {{{ */
{
	CURLcode cres, ctres, crres;
	CURL *curl;
	struct curl_slist *curl_headers = NULL;
	long l_code, response_code = -1;
	double d_code;
	zval info, *zca_info, *zca_path, *cur_val;
	char *s_code, *content_type = NULL, *bufz = NULL;
	char *auth_type = NULL;
	uint sslcheck;
	zend_string *cur_key;
	ulong num_key;
	smart_str sheader = {0};

	auth_type = Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD));
	zca_info = soo_get_property(soo, OAUTH_ATTR_CA_INFO);
	zca_path = soo_get_property(soo, OAUTH_ATTR_CA_PATH);
	sslcheck = soo->sslcheck;

	curl = curl_easy_init();

	if (request_headers) {
		for (zend_hash_internal_pointer_reset(request_headers);
				(cur_val = zend_hash_get_current_data(request_headers)) != NULL;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key is used */
			if (zend_hash_get_current_key_ex(request_headers, &cur_key, &num_key, 0, NULL) != HASH_KEY_IS_STRING) {
				continue;
			}
			if (Z_TYPE_P(cur_val) != IS_STRING) {
				continue;
			}
			smart_str_appendl(&sheader, cur_key->val, cur_key->len);
			smart_str_appends(&sheader, ": ");
			smart_str_appendl(&sheader, Z_STRVAL_P(cur_val), Z_STRLEN_P(cur_val));

			smart_str_0(&sheader);
			curl_headers = curl_slist_append(curl_headers, sheader.s->val);
			smart_str_free(&sheader);
		}
	}

	if(soo->is_multipart) {
		struct curl_httppost *ff = NULL;
		struct curl_httppost *lf = NULL;
		int i;

		for(i=0; i < soo->multipart_files_num; i++) {
			const char *type, *filename;
			char *postval;
			
			/* swiped from ext/curl/interface.c to help with consistency */
			postval = estrdup(soo->multipart_files[i]);

			if (postval[0] == '@' && soo->multipart_params[i][0] == '@') {
				/* :< (chomp) @ */
				++soo->multipart_params[i];
				++postval;
				
				if((type = php_memnstr(postval, ";type=", sizeof(";type=") - 1, postval + strlen(soo->multipart_files[i]) - 1))) {
					postval[type - postval] = '\0';
				}
				if((filename = php_memnstr(postval, ";filename=", sizeof(";filename=") - 1, postval + strlen(soo->multipart_files[i]) - 1))) {
					postval[filename - postval] = '\0';
				}
				
				/* open_basedir check */
				if(php_check_open_basedir(postval TSRMLS_CC)) {
					char *em;
					zend_spprintf(&em, 0, "failed to open file for multipart request: %s", postval);
					soo_handle_error(soo, -1, em, NULL, NULL TSRMLS_CC);
					efree(em);
					return 1;
				}
				
				curl_formadd(&ff, &lf,
							 CURLFORM_COPYNAME, soo->multipart_params[i],
							 CURLFORM_NAMELENGTH, (long)strlen(soo->multipart_params[i]),
							 CURLFORM_FILENAME, filename ? filename + sizeof(";filename=") - 1 : soo->multipart_files[i],
							 CURLFORM_CONTENTTYPE, type ? type + sizeof(";type=") - 1 : "application/octet-stream",
							 CURLFORM_FILE, postval,
							 CURLFORM_END);
			} else {
				curl_formadd(&ff, &lf,
							 CURLFORM_COPYNAME, soo->multipart_params[i],
							 CURLFORM_NAMELENGTH, (long)strlen(soo->multipart_params[i]),
							 CURLFORM_COPYCONTENTS, postval,
							 CURLFORM_CONTENTSLENGTH, (long)strlen(postval),
							 CURLFORM_END);
			}
		}

		curl_easy_setopt(curl, CURLOPT_HTTPPOST, ff);
	} else if (payload->s->len) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload->s->val);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload->s->len);
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* the fetch method takes precedence so figure it out after we've added the OAuth params */
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method);

	/* Disable sending the 100 Expect header for POST requests */
	/* Other notes: if there is a redirect the POST becomes a GET request, see curl_easy_setopt(3) and the CURLOPT_POSTREDIR option for more information */
	curl_headers = curl_slist_append(curl_headers, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, OAUTH_USER_AGENT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, soo_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, soo);
	if(sslcheck == OAUTH_SSLCHECK_NONE) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	} else {
		if (!(sslcheck & OAUTH_SSLCHECK_HOST)) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		}
		if (!(sslcheck & OAUTH_SSLCHECK_PEER)) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		}
		if (zca_path && Z_STRLEN_P(zca_path)) {
			curl_easy_setopt(curl, CURLOPT_CAPATH, Z_STRVAL_P(zca_path));
		}
		if (zca_info && Z_STRLEN_P(zca_info)) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, Z_STRVAL_P(zca_info));
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

#if LIBCURL_VERSION_NUM > 0x071002
	if(soo->timeout) {
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, soo->timeout);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, soo->timeout);
	}
#endif

	smart_str_free(&soo->lastresponse);
	smart_str_free(&soo->headers_in);

	if(soo->debug) {
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, oauth_debug_handler);
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, soo->debug_info);
	}

	cres = curl_easy_perform(curl);

	smart_str_0(&soo->lastresponse);
	smart_str_0(&soo->headers_in);

	if (curl_headers) {
		curl_slist_free_all(curl_headers);
	}

	if (CURLE_OK == cres) {
		ctres = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (CURLE_OK == crres && ctres == CURLE_OK) {
			ZVAL_NEW_ARR(&info);

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
			
			CAAS("headers_recv", soo->headers_in.s->val);

			so_set_response_info(soo->properties, &info);
		}
	} else {
		zend_spprintf(&bufz, 0, "making the request failed (%s)", curl_easy_strerror(cres));
		soo_handle_error(soo, -1, bufz, soo->lastresponse.s->val, NULL TSRMLS_CC);
		efree(bufz);
	}
	curl_easy_cleanup(curl);
	return response_code;
}
/* }}} */
#endif

static void make_standard_query(HashTable *ht, php_so_object *soo TSRMLS_DC) /* {{{ */
{
	char *ts, *nonce;

	if (soo->timestamp) {
		ts = estrdup(soo->timestamp);
	} else {
		time_t now = time(NULL);
		/* XXX allow caller to set timestamp, if none set, then default to "now" */
		zend_spprintf(&ts, 0, "%d", (int)now);
	}

	if (soo->nonce) {
		nonce = estrdup(soo->nonce);
	} else {
		struct timeval tv;
		int sec, usec;
		/* XXX maybe find a better way to generate a nonce... */
		gettimeofday((struct timeval *) &tv, (struct timezone *) NULL);
		sec = (int) tv.tv_sec;
		usec = (int) (tv.tv_usec % 0x100000);
		spprintf(&nonce, 0, "%ld%08x%05x%.8f", php_rand(TSRMLS_C), sec, usec, php_combined_lcg(TSRMLS_C) * 10);
	}

	add_arg_for_req(ht, OAUTH_PARAM_CONSUMER_KEY, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_CONSUMER_KEY)) TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_SIGNATURE_METHOD, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_SIGMETHOD)) TSRMLS_CC);

	add_arg_for_req(ht, OAUTH_PARAM_NONCE, nonce TSRMLS_CC);

	add_arg_for_req(ht, OAUTH_PARAM_TIMESTAMP, ts TSRMLS_CC);
	add_arg_for_req(ht, OAUTH_PARAM_VERSION, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_OAUTH_VERSION)) TSRMLS_CC);

	efree(ts); efree(nonce);
}
/* }}} */

/*
Returns the default http method to use with the different auth types
*/
static const char *oauth_get_http_method(php_so_object *soo, const char *http_method TSRMLS_DC) /* {{{ */
{
	long auth_type = Z_LVAL_P(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD));

	if (http_method) {
		/* TODO handle conflict with FORM auth and anything but POST or PUT */
		return http_method;
	}
	/* http method not explicitly given, choose default one */
	if (OAUTH_AUTH_TYPE_FORM == auth_type) {
		return OAUTH_HTTP_METHOD_POST;
	} else {
		return OAUTH_HTTP_METHOD_GET;
	}
}
/* }}} */

/*
Modifies (and returns) passed url parameter to be used for additional parameter appending
*/
static smart_str *http_prepare_url_concat(smart_str *surl) /* {{{ */
{
	smart_str_0(surl);
	if (memchr(surl->s->val, '?', surl->s->len) == NULL) {
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

	/* determine whether location is relative */
	if ('/'==*location) {
		urlparts = php_url_parse_ex(surl->s->val, surl->s->len);

		/* rebuild url from scratch */
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
	char *sbs = NULL, *bufz = NULL;
	zend_string *sig = NULL;
	const char *final_http_method;
	zval *token = NULL, *cs;
	zval *ts = NULL, *token_secret = NULL;
	zval zret;
	HashTable *oauth_args = NULL;
	HashTable *rargs = NULL, *rheaders = NULL;
	long http_response_code, auth_type;
	smart_str surl = {0}, payload = {0}, postdata = {0};
	uint is_redirect = FALSE, follow_redirects = 0, need_to_free_rheaders = 0;

	auth_type = Z_LVAL_P(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD));
	if (fetch_flags & OAUTH_OVERRIDE_HTTP_METHOD) {
		final_http_method = method;
	} else {
		final_http_method = oauth_get_http_method(soo, method ? method : OAUTH_HTTP_METHOD_POST TSRMLS_CC);

		if (OAUTH_AUTH_TYPE_FORM==auth_type && strcasecmp(final_http_method, OAUTH_HTTP_METHOD_POST) != 0) {
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "auth type is set to HTTP POST with a non-POST http method, use setAuthType to put OAuth parameters somewhere else in the request", NULL, NULL TSRMLS_CC);
		}
	}

	if(!final_http_method) {
		final_http_method = "GET";
	}

	follow_redirects = soo->follow_redirects;
	soo->redirects = 0;
	soo->multipart_files = NULL;
	soo->multipart_params = NULL;
	soo->multipart_files_num = 0;
	soo->is_multipart = 0;

	/* request_params can be either NULL, a string containing arbitrary text (such as XML) or an array */
	if (request_params) {
		switch (Z_TYPE_P(request_params)) {
		case IS_ARRAY:
			rargs = HASH_OF(request_params);
			oauth_http_build_query(soo, &postdata, rargs, FALSE TSRMLS_CC);
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
		need_to_free_rheaders = 1;
	} else {
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
			/* populate oauth_args with given parameters */
			zend_hash_copy(oauth_args, init_oauth_args, (copy_ctor_func_t) zval_add_ref);
		}

		/* fill in the standard set of oauth parameters */
		make_standard_query(oauth_args, soo TSRMLS_CC);

		/* use token where applicable */
		if (fetch_flags & OAUTH_FETCH_USETOKEN) {
			token = soo_get_property(soo, OAUTH_ATTR_TOKEN);
			if (token) {
				add_arg_for_req(oauth_args, OAUTH_PARAM_TOKEN, Z_STRVAL_P(token) TSRMLS_CC);
			}
		}

		/* generate sig base on the semi-final url */
		smart_str_0(&surl);
		sbs = oauth_generate_sig_base(soo, final_http_method, surl.s->val, oauth_args, rargs TSRMLS_CC);
		if (!sbs) {
			FREE_ARGS_HASH(oauth_args);
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url, unable to generate signature base string", NULL, NULL TSRMLS_CC);
			break;
		}

		cs = soo_get_property(soo, OAUTH_ATTR_CONSUMER_SECRET);
		SEPARATE_ZVAL(cs);

		/* determine whether token should be used to sign the request */
		if (fetch_flags & OAUTH_FETCH_USETOKEN) {
			token_secret = soo_get_property(soo, OAUTH_ATTR_TOKEN_SECRET);
			if (token_secret && Z_STRLEN_P(token_secret) > 0) {
				ts = token_secret;
			}
		}

		if (soo->signature) {
			STR_FREE(soo->signature);
		}
		/* sign the request */
		sig = soo_sign(soo, sbs, cs, ts, soo->sig_ctx TSRMLS_CC);
		soo->signature = sig;
		efree(sbs);

		if(fetch_flags & OAUTH_FETCH_SIGONLY) {
			FREE_ARGS_HASH(oauth_args);
			smart_str_free(&surl);
			smart_str_free(&postdata);
			if(need_to_free_rheaders) {
				FREE_ARGS_HASH(rheaders);
			}
			return SUCCESS;
		}

		if (!sig) {
			FREE_ARGS_HASH(oauth_args);
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Signature generation failed", NULL, NULL TSRMLS_CC);
			break;
		}

		/* and add signature to the oauth parameters */
		add_arg_for_req(oauth_args, OAUTH_PARAM_SIGNATURE, sig->val TSRMLS_CC);

		if(fetch_flags & OAUTH_FETCH_HEADONLY) {
			smart_str_free(&soo->headers_out);
			oauth_add_signature_header(rheaders, oauth_args, &soo->headers_out TSRMLS_CC);
			smart_str_0(&payload);
			FREE_ARGS_HASH(oauth_args);
			smart_str_free(&surl);
			smart_str_free(&postdata);
			if(need_to_free_rheaders) {
				FREE_ARGS_HASH(rheaders);
			}
			return SUCCESS;
		}

		if (!strcmp(final_http_method, OAUTH_HTTP_METHOD_GET)) {
			/* GET request means to extend the url, but not for redirects obviously */
			if (!is_redirect && postdata.s->len) {
				smart_str_appendl(http_prepare_url_concat(&surl), postdata.s->val, postdata.s->len);
			}
		} else {
			/* otherwise populate post data */
			smart_str_append(&payload, &postdata);
		}

		switch (auth_type) {
			case OAUTH_AUTH_TYPE_FORM:
				/* append/set post data with oauth parameters */
				oauth_http_build_query(soo, &payload, oauth_args, payload.s->len TSRMLS_CC);
				smart_str_0(&payload);
				break;

			case OAUTH_AUTH_TYPE_URI:
				/* extend url request with oauth parameters */
				if (!is_redirect) {
					oauth_http_build_query(soo, http_prepare_url_concat(&surl), oauth_args, FALSE TSRMLS_CC);
				}
				/* TODO look into merging oauth parameters if they occur in the current url */
				break;

			case OAUTH_AUTH_TYPE_AUTHORIZATION:
				/* add http header with oauth parameters */
				oauth_add_signature_header(rheaders, oauth_args, NULL TSRMLS_CC);
				break;
		}

		/* finalize endpoint url */
		smart_str_0(&surl);

		if (soo->debug) {
			FREE_DEBUG_INFO(soo->debug_info);
			INIT_DEBUG_INFO(soo->debug_info);
		}

		switch (soo->reqengine) {
			case OAUTH_REQENGINE_STREAMS:
				http_response_code = make_req_streams(soo, surl.s->val, &payload, final_http_method, rheaders TSRMLS_CC);
				break;
#if OAUTH_USE_CURL
			case OAUTH_REQENGINE_CURL:
				http_response_code = make_req_curl(soo, surl.s->val, &payload, final_http_method, rheaders TSRMLS_CC);
				if (soo->multipart_files_num) {
					efree(soo->multipart_files);
					efree(soo->multipart_params);
					soo->multipart_files_num = 0;
					soo->is_multipart = 0;
				}
				break;
#endif
		}

		is_redirect = HTTP_IS_REDIRECT(http_response_code);

		if(soo->debug) {
			oauth_set_debug_info(soo TSRMLS_CC);
		}

		FREE_ARGS_HASH(oauth_args);
		smart_str_free(&payload);

		if (is_redirect) {
			if (follow_redirects) {
				if (soo->redirects >= OAUTH_MAX_REDIRS) {
					zend_spprintf(&bufz, 0, "max redirections exceeded (max: %ld last redirect url: %s)", OAUTH_MAX_REDIRS, soo->last_location_header);
					if (soo->lastresponse.s->len) {
						ZVAL_STRING(&zret, soo->lastresponse.s->val);
					} else {
						ZVAL_STRING(&zret, "");
					}
					so_set_response_args(soo->properties, &zret, NULL TSRMLS_CC);
					soo_handle_error(soo, http_response_code, bufz, soo->lastresponse.s->val, NULL TSRMLS_CC);
					efree(bufz);
					/* set http_response_code to error value */
					http_response_code = -1;
					break;
				} else {
					++soo->redirects;
					oauth_apply_url_redirect(&surl, soo->last_location_header);
					smart_str_0(&surl);
/* bug 22628; keep same method when following redirects
					final_http_method = OAUTH_HTTP_METHOD_GET;
*/
				}
			}
		} else if (http_response_code < 0) {
			/* exception would have been thrown already */
		} else if (http_response_code < 200 || http_response_code > 206) {
			zend_spprintf(&bufz, 0, "Invalid auth/bad request (got a %ld, expected HTTP/1.1 20X or a redirect)", http_response_code);
			if(soo->lastresponse.s->len) {
				ZVAL_STRING(&zret, soo->lastresponse.s->val);
			} else {
				ZVAL_STRING(&zret, "");
			}
			so_set_response_args(soo->properties, &zret, NULL TSRMLS_CC);
			soo_handle_error(soo, http_response_code, bufz, soo->lastresponse.s->val, NULL TSRMLS_CC);
			efree(bufz);
			/* set http_response_code to error value */
			http_response_code = -1;
			break;
		} else {
			/* valid response, time to get out of this loop */
		}
	} while (is_redirect && follow_redirects);

	smart_str_free(&surl);
	smart_str_free(&postdata);
	if(need_to_free_rheaders) {
		FREE_ARGS_HASH(rheaders);
	}

	return http_response_code;
}
/* }}} */

SO_METHOD(setRSACertificate)
{
	char *key;
	int key_len;
	zval args[1], func, retval;

	php_so_object *soo;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len) == FAILURE) {
		return;
	}

	ZVAL_STRING(&func, "openssl_get_privatekey");

	ZVAL_STRINGL(&args[0], key, key_len);

	call_user_function(EG(function_table), NULL, &func, &retval, 1, args TSRMLS_CC);

	zval_ptr_dtor(&args[0]);
	zval_ptr_dtor(&func);

	if (Z_TYPE(retval) == IS_RESOURCE) {
		OAUTH_SIGCTX_SET_PRIVATEKEY(soo->sig_ctx, retval);
		RETURN_TRUE;
	} else {
		zval_ptr_dtor(&retval);
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Could not parse RSA certificate", NULL, NULL TSRMLS_CC);
		return;
	}
}

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
		RETURN_FALSE;
	}
	RETURN_STR(oauth_url_encode(uri, uri_len));
}
/* }}} */

/* {{{ proto string oauth_get_sbs(string http_method, string uri, array parameters)
   Get a signature base string */
PHP_FUNCTION(oauth_get_sbs)
{
	char *uri, *http_method, *sbs;
	int uri_len, http_method_len;
	zval *req_params = NULL;
	HashTable *rparams = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|a", &http_method, &http_method_len, &uri, &uri_len, &req_params) == FAILURE) {
		return;
	}

	if (uri_len < 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid uri length (0)");
		RETURN_FALSE;
	}

	if (http_method_len < 1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid http method length (0)");
		RETURN_FALSE;
	}

	if (req_params) {
		rparams = HASH_OF(req_params);
	}

	if ((sbs = oauth_generate_sig_base(NULL, http_method, uri, NULL, rparams TSRMLS_CC))) {
		RETVAL_STRING(sbs);
		efree(sbs);
		return;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* only hmac-sha1 is supported at the moment (it is the most common implementation), still need to lay down the ground work for supporting plaintext and others */

/* {{{ proto void OAuth::__construct(string consumer_key, string consumer_secret [, string signature_method, [, string auth_type ]])
   Instantiate a new OAuth object */
SO_METHOD(__construct)
{
	HashTable *hasht;
	char *ck, *cs, *sig_method = NULL;
	long auth_method = 0;
	zval zck, zcs, zsm, zam, zver, *obj;
	int ck_len, cs_len, sig_method_len = 0;
	php_so_object *soo;
	zend_error_handling error_handling;

	zend_replace_error_handling(EH_THROW, oauth_exception_class_entry, &error_handling TSRMLS_CC);
	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss|sl", &obj, oauth_class_entry, &ck, &ck_len, &cs, &cs_len, &sig_method, &sig_method_len, &auth_method) == FAILURE) {
		zend_restore_error_handling(&error_handling TSRMLS_CC);
		return;
	}

	zend_restore_error_handling(&error_handling TSRMLS_CC);
	soo = Z_OAUTHOBJ_P(obj);

	if(!ck_len) {
		zend_throw_exception(oauth_exception_class_entry, "The consumer key cannot be empty", 0 TSRMLS_CC);
		return;
	}
/*
	if(!cs_len) {
		soo_handle_error(soo, -1, "The consumer secret cannot be empty", NULL, NULL TSRMLS_CC);
		php_error(E_ERROR, "the consumer secret cannot be empty");
		return;
	}
*/

	/* set default class members */
	zend_update_property_null(oauth_class_entry, obj, "debugInfo", sizeof("debugInfo") - 1 TSRMLS_CC);
	zend_update_property_bool(oauth_class_entry, obj, "debug", sizeof("debug") - 1, soo->debug TSRMLS_CC);
	zend_update_property_long(oauth_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, soo->sslcheck TSRMLS_CC);

	TSRMLS_SET_CTX(soo->thread_ctx);

	if (!sig_method_len) {
		sig_method = OAUTH_SIG_METHOD_HMACSHA1;
	}

	soo->sig_ctx = oauth_create_sig_context(sig_method);

	if (!auth_method) {
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

	ZVAL_STRING(&zck, ck);
	if (soo_set_property(soo, &zck, OAUTH_ATTR_CONSUMER_KEY TSRMLS_CC) != SUCCESS) {
		return;
	}

	if (cs_len > 0) {
		ZVAL_STR(&zcs, oauth_url_encode(cs, cs_len));
	} else {
		ZVAL_EMPTY_STRING(&zcs);
	}
	if (soo_set_property(soo, &zcs, OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC) != SUCCESS) {
		return;
	}

	ZVAL_STRING(&zsm, sig_method);
	if (soo_set_property(soo, &zsm, OAUTH_ATTR_SIGMETHOD TSRMLS_CC) != SUCCESS) {
		return;
	}

	ZVAL_LONG(&zam, auth_method);
	if (soo_set_property(soo, &zam, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC) != SUCCESS) {
		return;
	}

	ZVAL_STRING(&zver, OAUTH_DEFAULT_VERSION);
	if (soo_set_property(soo, &zver, OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC) != SUCCESS) {
		return;
	}
}
/* }}} */

void oauth_free_privatekey(zval *privatekey TSRMLS_DC)
{
	zval func, retval;
	zval args[1];

	if (Z_TYPE_P(privatekey)==IS_RESOURCE) {
		ZVAL_UNDEF(&retval);

		ZVAL_STRING(&func, "openssl_freekey");
		args[0] = *privatekey;

		call_user_function(EG(function_table), NULL, &func, &retval, 1, args TSRMLS_CC);

		zval_ptr_dtor(&func);
		zval_ptr_dtor(&retval);
	}

	zval_ptr_dtor(privatekey);
}

#if 0
/* {{{ proto void OAuth::__destruct(void)
   clean up of OAuth object */
SO_METHOD(__destruct)
{
	php_so_object *soo;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O", &id, oauth_object_class_entry) == FAILURE) {
		return;
	}

}
/* }}} */
#endif

/* {{{ proto array OAuth::setCAPath(string ca_path, string ca_info)
   Set the Certificate Authority information */
SO_METHOD(setCAPath)
{
	php_so_object *soo;
	char *ca_path, *ca_info;
	int ca_path_len = 0, ca_info_len = 0;
	zval zca_path, zca_info;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss", &ca_path, &ca_path_len, &ca_info, &ca_info_len) == FAILURE) {
		return;
	}

	if (ca_path_len) {
		ZVAL_STRINGL(&zca_path, ca_path, ca_path_len);
		if (soo_set_property(soo, &zca_path, OAUTH_ATTR_CA_PATH TSRMLS_CC) != SUCCESS) {
			RETURN_FALSE;
		}
	}

	if (ca_info_len) {
		ZVAL_STRINGL(&zca_info, ca_info, ca_info_len);
		if (soo_set_property(soo, &zca_info, OAUTH_ATTR_CA_INFO TSRMLS_CC) != SUCCESS) {
			RETURN_FALSE;
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
	zval *zca_path, *zca_info;

	soo = Z_OAUTHOBJ_P(getThis());
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	zca_info = soo_get_property(soo, OAUTH_ATTR_CA_INFO);
	zca_path = soo_get_property(soo, OAUTH_ATTR_CA_PATH);

	array_init(return_value);

	if (zca_info || zca_path) {
		if(zca_info) {
			add_assoc_stringl(return_value, "ca_info", Z_STRVAL_P(zca_info), Z_STRLEN_P(zca_info));
		}

		if(zca_path) {
			add_assoc_stringl(return_value, "ca_path", Z_STRVAL_P(zca_path), Z_STRLEN_P(zca_path));
		}
	}
}
/* }}} */

/* {{{ proto array OAuth::getRequestToken(string request_token_url [, string callback_url ])
   Get request token */
SO_METHOD(getRequestToken)
{
	php_so_object *soo;
	zval zret, *callback_url = NULL;
	char *url, *http_method = NULL;
	int url_len = 0, http_method_len = 0;
	long retcode;
	HashTable *args = NULL;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zs", &url, &url_len, &callback_url, &http_method, &http_method_len) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid request token url length", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	if (callback_url && IS_STRING==Z_TYPE_P(callback_url)) {
		ALLOC_HASHTABLE(args);
		zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
		if (Z_STRLEN_P(callback_url) > 0) {
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, Z_STRVAL_P(callback_url) TSRMLS_CC);
		} else {
			/* empty callback url specified, treat as 1.0a */
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, OAUTH_CALLBACK_OOB TSRMLS_CC);
		}
	}

	retcode = oauth_fetch(soo, url, oauth_get_http_method(soo, http_method TSRMLS_CC), NULL, NULL, args, 0 TSRMLS_CC);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.s->len) {
		ZVAL_STR(&zret, soo->lastresponse.s);
		so_set_response_args(soo->properties, &zret, return_value TSRMLS_CC);
		return;
	}
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool OAuth::enableRedirects(void)
   Follow and sign redirects automatically (enabled by default) */
SO_METHOD(enableRedirects)
{
	php_so_object *soo;

	soo = Z_OAUTHOBJ_P(getThis());
	
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

	soo = Z_OAUTHOBJ_P(getThis());

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
	zval *obj;

	obj = getThis();
	soo = Z_OAUTHOBJ_P(obj);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->debug = 0;
	zend_update_property_bool(oauth_class_entry, obj, "debug", sizeof("debug") - 1, 0 TSRMLS_CC);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableDebug(void)
   Enable debug mode, will verbosely output http information about requests */
SO_METHOD(enableDebug)
{
	php_so_object *soo;
	zval *obj;

	obj = getThis();
	soo = Z_OAUTHOBJ_P(obj);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->debug = 1;
	zend_update_property_bool(oauth_class_entry, obj, "debug", sizeof("debug") - 1, 1 TSRMLS_CC);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::enableSSLChecks(void)
   Enable SSL verification for requests, enabled by default */
SO_METHOD(enableSSLChecks)
{
	php_so_object *soo;
	zval *obj;

	obj = getThis();
	soo = Z_OAUTHOBJ_P(obj);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->sslcheck = OAUTH_SSLCHECK_BOTH;
	zend_update_property_long(oauth_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, 1 TSRMLS_CC);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::disableSSLChecks(void)
   Disable SSL verification for requests (be careful using this for production) */
SO_METHOD(disableSSLChecks)
{
	php_so_object *soo;
	zval *obj;

	obj = getThis();
	soo = Z_OAUTHOBJ_P(obj);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo->sslcheck = OAUTH_SSLCHECK_NONE;
	zend_update_property_long(oauth_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, 0 TSRMLS_CC);

	RETURN_TRUE;
}
/* }}} */


/* {{{ proto bool OAuth::setSSLChecks(long sslcheck)
   Tweak specific SSL checks for requests (be careful using this for production) */
SO_METHOD(setSSLChecks)
{
	php_so_object *soo;
	zval *obj;
	long sslcheck = OAUTH_SSLCHECK_BOTH;

	obj = getThis();
	soo = Z_OAUTHOBJ_P(obj);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &sslcheck) == FAILURE) {
		return;
	}

	soo->sslcheck = sslcheck & OAUTH_SSLCHECK_BOTH;

	zend_update_property_long(oauth_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, 
			soo->sslcheck TSRMLS_CC);

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
	zval zver;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &vers, &ver_len) == FAILURE) {
		return;
	}

	if (ver_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid version", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	ZVAL_STRING(&zver, vers);
	if (SUCCESS==soo_set_property(soo, &zver, OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC)) {
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
	long auth;
	zval zauth;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &auth) == FAILURE) {
		return;
	}

	switch (auth) {
		case OAUTH_AUTH_TYPE_URI:
		case OAUTH_AUTH_TYPE_FORM:
		case OAUTH_AUTH_TYPE_AUTHORIZATION:
		case OAUTH_AUTH_TYPE_NONE:
			ZVAL_LONG(&zauth, auth);
			if (SUCCESS==soo_set_property(soo, &zauth, OAUTH_ATTR_AUTHMETHOD TSRMLS_CC)) {
				RETURN_TRUE;
			}

		default:
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL, NULL TSRMLS_CC);
			RETURN_FALSE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool OAuth::setTimeout(int milliseconds)
   Set the timeout, in milliseconds, for requests */
SO_METHOD(setTimeout)
{
	php_so_object *soo;
	long timeout;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout) == FAILURE) {
		return;
	}

	if (timeout < 0) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid timeout", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	soo->timeout = timeout;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool OAuth::setNonce(string nonce)
   Set oauth_nonce for subsequent requests, if none is set a random nonce will be generated using uniqid */
SO_METHOD(setNonce)
{
	php_so_object *soo;
	int nonce_len;
	char *nonce;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &nonce, &nonce_len) == FAILURE) {
		return;
	}

	if (nonce_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid nonce", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	if (soo->nonce) {
		efree(soo->nonce);
	}
	soo->nonce = estrndup(nonce, nonce_len);

	RETURN_TRUE;
}
/* }}} */

SO_METHOD(setTimestamp)
{
	php_so_object *soo;
	int ts_len;
	char *ts;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &ts, &ts_len) == FAILURE) {
		return;
	}

	if (ts_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid timestamp", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	if (soo->timestamp) {
		efree(soo->timestamp);
	}
	soo->timestamp = estrndup(ts, ts_len);

	RETURN_TRUE;
}

/* {{{ proto bool OAuth::setToken(string token, string token_secret)
   Set a request or access token and token secret to be used in subsequent requests */
SO_METHOD(setToken)
{
	php_so_object *soo;
	int token_len, token_secret_len;
	char *token, *token_secret;
	zval t, ts;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &token, &token_len, &token_secret, &token_secret_len) == FAILURE) {
		return;
	}

	ZVAL_STRING(&t, token);
	soo_set_property(soo, &t, OAUTH_ATTR_TOKEN TSRMLS_CC);

	if (token_secret_len > 1) {
		ZVAL_STR(&ts, oauth_url_encode(token_secret, token_secret_len));
		soo_set_property(soo, &ts, OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto void OAuth::setRequestEngine(long reqengine) */
SO_METHOD(setRequestEngine)
{
	php_so_object *soo;
	long reqengine;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &reqengine) == FAILURE) {
		return;
	}
	soo = Z_OAUTHOBJ_P(getThis());

	switch (reqengine) {
		case OAUTH_REQENGINE_STREAMS:
#if OAUTH_USE_CURL
		case OAUTH_REQENGINE_CURL:
#endif
			soo->reqengine = reqengine;
			break;

		default:
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid request engine specified", NULL, NULL TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto bool OAuth::generateSignature(string http_method, string url [, string|array extra_parameters ])
   Generate a signature based on the final HTTP method, URL and a string/array of parameters */
SO_METHOD(generateSignature)
{
	php_so_object *soo;
	int url_len, http_method_len = 0;
	char *url;
	zval *request_args = NULL;
	char *http_method = NULL;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &http_method, &http_method_len, &url, &url_len, &request_args) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		RETURN_BOOL(FALSE);
	}

	if (oauth_fetch(soo, url, http_method, request_args, NULL, NULL, (OAUTH_FETCH_USETOKEN | OAUTH_FETCH_SIGONLY) TSRMLS_CC) < 0) {
		RETURN_BOOL(FALSE);
	} else {
		RETURN_STR(soo->signature);
	}
}
/* }}} */

/* {{{ proto bool OAuth::fetch(string protected_resource_url [, string|array extra_parameters [, string request_type [, array request_headers]]])
   fetch a protected resource, pass in extra_parameters (array(name => value) or "custom body") */
SO_METHOD(fetch)
{
	php_so_object *soo;
	int fetchurl_len, http_method_len = 0;
	char *fetchurl;
	zval zret, *request_args = NULL, *request_headers = NULL;
	char *http_method = NULL;
	long retcode;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|zsa", &fetchurl, &fetchurl_len, &request_args, &http_method, &http_method_len, &request_headers) == FAILURE) {
		return;
	}

	if (fetchurl_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url length", NULL, NULL TSRMLS_CC);
		RETURN_FALSE;
	}

	retcode = oauth_fetch(soo, fetchurl, http_method, request_args, request_headers, NULL, OAUTH_FETCH_USETOKEN | OAUTH_OVERRIDE_HTTP_METHOD TSRMLS_CC);

	ZVAL_STR(&zret, soo->lastresponse.s);
	so_set_response_args(soo->properties, &zret, NULL TSRMLS_CC);

	if ((retcode < 200 || retcode > 206)) {
		RETURN_FALSE;
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
	int aturi_len = 0, ash_len = 0, verifier_len = 0, http_method_len = 0;
	char *aturi, *ash, *verifier, *http_method = NULL;
	zval zret;
	HashTable *args = NULL;
	long retcode;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sss", &aturi, &aturi_len, &ash, &ash_len, &verifier, &verifier_len, &http_method, &http_method_len) == FAILURE) {
		return;
	}

	if (aturi_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid access token url length", NULL, NULL TSRMLS_CC);
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

	retcode = oauth_fetch(soo, aturi, oauth_get_http_method(soo, http_method TSRMLS_CC), NULL, NULL, args, OAUTH_FETCH_USETOKEN TSRMLS_CC);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.s->len) {
		array_init(return_value);
		ZVAL_STR(&zret, soo->lastresponse.s);
		so_set_response_args(soo->properties, &zret, return_value TSRMLS_CC);
		return;
	}
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto array OAuth::getLastResponseInfo(void)
   Get information about the last response */
SO_METHOD(getLastResponseInfo)
{
	php_so_object *soo;
	zval *data_ptr;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}

	soo = Z_OAUTHOBJ_P(getThis());

	if ((data_ptr = zend_hash_str_find(soo->properties, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO)))) {
		if (Z_TYPE_P(data_ptr) == IS_ARRAY) {
			convert_to_array_ex(data_ptr);
		}
		RETURN_ZVAL(data_ptr, 1, 0);
	}
	RETURN_FALSE;
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

	soo = Z_OAUTHOBJ_P(getThis());

	if (soo->lastresponse.s->len) {
		RETURN_STR(soo->lastresponse.s);
	}
}
/* }}} */

SO_METHOD(getLastResponseHeaders)
{
	php_so_object *soo;

	if (FAILURE==zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "")) {
		return;
	}

	soo = Z_OAUTHOBJ_P(getThis());
	if (soo->headers_in.s->len) {
		RETURN_STR(soo->headers_in.s);
	}
	RETURN_FALSE;
}

/* {{{ proto string OAuth::getRequestHeader(string http_method, string url [, string|array extra_parameters ])
   Generate OAuth header string signature based on the final HTTP method, URL and a string/array of parameters */
SO_METHOD(getRequestHeader)
{
	php_so_object *soo;
	int url_len, http_method_len = 0;
	char *url;
	zval *request_args = NULL;
	char *http_method = NULL;

	soo = Z_OAUTHOBJ_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|z", &http_method, &http_method_len, &url, &url_len, &request_args) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		RETURN_BOOL(FALSE);
	}

	if (oauth_fetch(soo, url, http_method, request_args, NULL, NULL, 
				(OAUTH_FETCH_USETOKEN | OAUTH_FETCH_HEADONLY) TSRMLS_CC) < 0) {
		RETURN_BOOL(FALSE);
	} else {
		RETURN_STR(soo->headers_out.s);
	}

	RETURN_FALSE;
}

/* {{{ arginfo */
OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_urlencode, 0, 0, 1)
	ZEND_ARG_INFO(0, uri)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_sbs, 0, 0, 3)
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
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setnonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settimestamp, 0, 0, 1)
	ZEND_ARG_INFO(0, ts)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settimeout, 0, 0, 1)
	ZEND_ARG_INFO(0, timeout_in_milliseconds)
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
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setrequestengine, 0, 0, 1)
	ZEND_ARG_INFO(0, reqengine)
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

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setrsacertificate, 0, 0, 1)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_gensig, 0, 0, 2)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setsslchecks, 0, 0, 1)
	ZEND_ARG_INFO(0, sslcheck)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getrequestheader, 0, 0, 2)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
ZEND_END_ARG_INFO()


/* }}} */


static zend_function_entry oauth_functions[] = { /* {{{ */
	SO_ME(__construct,			arginfo_oauth__construct,		ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
	SO_ME(setRSACertificate,	arginfo_oauth_setrsacertificate,	ZEND_ACC_PUBLIC)
	SO_ME(getRequestToken,		arginfo_oauth_getrequesttoken,	ZEND_ACC_PUBLIC)
	SO_ME(getAccessToken,		arginfo_oauth_getaccesstoken,	ZEND_ACC_PUBLIC)
	SO_ME(getLastResponse,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(getLastResponseInfo,	arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(getLastResponseHeaders,	arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(setToken,				arginfo_oauth_settoken,			ZEND_ACC_PUBLIC)
	SO_ME(setRequestEngine,		arginfo_oauth_setrequestengine, 		ZEND_ACC_PUBLIC)
	SO_ME(setVersion,			arginfo_oauth_setversion,		ZEND_ACC_PUBLIC)
	SO_ME(setAuthType,			arginfo_oauth_setauthtype,		ZEND_ACC_PUBLIC)
	SO_ME(setNonce,				arginfo_oauth_setnonce,			ZEND_ACC_PUBLIC)
	SO_ME(setTimestamp,			arginfo_oauth_settimestamp,		ZEND_ACC_PUBLIC)
	SO_ME(fetch,				arginfo_oauth_fetch,			ZEND_ACC_PUBLIC)
	SO_ME(enableDebug,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableDebug,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(enableSSLChecks,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableSSLChecks,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(enableRedirects,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(disableRedirects,		arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(setCAPath,			arginfo_oauth_setcapath,		ZEND_ACC_PUBLIC)
	SO_ME(getCAPath,			arginfo_oauth_noparams,			ZEND_ACC_PUBLIC)
	SO_ME(generateSignature,	arginfo_oauth_gensig,			ZEND_ACC_PUBLIC)
	SO_ME(setTimeout,			arginfo_oauth_settimeout,		ZEND_ACC_PUBLIC)
	SO_ME(setSSLChecks,			arginfo_oauth_setsslchecks,		ZEND_ACC_PUBLIC)
	SO_ME(getRequestHeader,		arginfo_oauth_getrequestheader,	ZEND_ACC_PUBLIC)
	PHP_FE(oauth_urlencode,		arginfo_oauth_urlencode)
	PHP_FE(oauth_get_sbs,		arginfo_oauth_sbs)
	{NULL, NULL, NULL}
};
/* }}} */

static zval *oauth_read_member(zval *object, zval *member, int type, zend_uint cache_slot, zval *rv TSRMLS_DC)
{
	zval *return_value = NULL;
	php_so_object *soo;

	soo = Z_OAUTHOBJ_P(object);

	return_value = OAUTH_READ_PROPERTY(object, member, type);

	if (strcasecmp(Z_STRVAL_P(member), "debug") == 0) {
		convert_to_boolean(return_value);
		ZVAL_BOOL(return_value, soo->debug);
	} else if(strcasecmp(Z_STRVAL_P(member), "sslChecks") == 0) {
		ZVAL_LONG(return_value, soo->sslcheck);
	}

	return return_value;
} /* }}} */

static void oauth_write_member(zval *object, zval *member, zval *value, zend_uint cache_slot TSRMLS_DC)
{
	char *property;
	php_so_object *soo;

	property = Z_STRVAL_P(member);
	soo = Z_OAUTHOBJ_P(object);

	if (strcasecmp(property, "debug") == 0) {
		convert_to_long_ex(value);
		soo->debug = Z_LVAL_P(value);
	} else if (strcasecmp(property, "sslChecks") == 0) {
		soo->sslcheck = Z_LVAL_P(value);
	}
	OAUTH_WRITE_PROPERTY(object, member, value);
} /* }}} */

/* {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION(oauth) 
{
	zend_class_entry ce;

#if OAUTH_USE_CURL
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		return FAILURE;
	}
#endif

	memcpy(&oauth_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	oauth_object_handlers.offset = XtOffsetOf(php_so_object, zo);
	oauth_object_handlers.read_property = oauth_read_member;
	oauth_object_handlers.write_property = oauth_write_member;
	oauth_object_handlers.clone_obj = oauth_object_clone;
	oauth_object_handlers.free_obj = oauth_object_free_storage;

	INIT_CLASS_ENTRY(ce, "OAuthException", NULL);
	oauth_exception_class_entry = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C) TSRMLS_CC);
	zend_declare_property_null(oauth_exception_class_entry, "lastResponse", sizeof("lastResponse") - 1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(oauth_exception_class_entry, "debugInfo", sizeof("debugInfo") - 1, ZEND_ACC_PUBLIC TSRMLS_CC);

	INIT_CLASS_ENTRY(ce, "OAuth", oauth_functions);
	ce.create_object = oauth_object_new;
	oauth_class_entry = zend_register_internal_class_ex(&ce, NULL TSRMLS_CC);

	zend_declare_property_long(oauth_class_entry, "debug", sizeof("debug")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_long(oauth_class_entry, "sslChecks", sizeof("sslChecks")-1, 1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_string(oauth_class_entry, "debugInfo", sizeof("debugInfo")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);

	REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_HMACSHA1", OAUTH_SIG_METHOD_HMACSHA1, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_HMACSHA256", OAUTH_SIG_METHOD_HMACSHA256, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_RSASHA1", OAUTH_SIG_METHOD_RSASHA1, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_PLAINTEXT", OAUTH_SIG_METHOD_PLAINTEXT, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_AUTH_TYPE_AUTHORIZATION", OAUTH_AUTH_TYPE_AUTHORIZATION, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_AUTH_TYPE_URI", OAUTH_AUTH_TYPE_URI, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_AUTH_TYPE_FORM", OAUTH_AUTH_TYPE_FORM, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_AUTH_TYPE_NONE", OAUTH_AUTH_TYPE_NONE, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_GET", OAUTH_HTTP_METHOD_GET, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_POST", OAUTH_HTTP_METHOD_POST, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_PUT", OAUTH_HTTP_METHOD_PUT, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_HEAD", OAUTH_HTTP_METHOD_HEAD, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("OAUTH_HTTP_METHOD_DELETE", OAUTH_HTTP_METHOD_DELETE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_REQENGINE_STREAMS", OAUTH_REQENGINE_STREAMS, CONST_CS | CONST_PERSISTENT);
#ifdef OAUTH_USE_CURL
	REGISTER_LONG_CONSTANT("OAUTH_REQENGINE_CURL", OAUTH_REQENGINE_CURL, CONST_CS | CONST_PERSISTENT);
#endif
	REGISTER_LONG_CONSTANT("OAUTH_SSLCHECK_NONE", OAUTH_SSLCHECK_NONE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_SSLCHECK_HOST", OAUTH_SSLCHECK_HOST, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_SSLCHECK_PEER", OAUTH_SSLCHECK_PEER, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_SSLCHECK_BOTH", OAUTH_SSLCHECK_BOTH, CONST_CS | CONST_PERSISTENT);

//	oauth_provider_register_class(TSRMLS_C);
	REGISTER_LONG_CONSTANT("OAUTH_OK", OAUTH_OK, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_BAD_NONCE", OAUTH_BAD_NONCE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_BAD_TIMESTAMP", OAUTH_BAD_TIMESTAMP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_CONSUMER_KEY_UNKNOWN", OAUTH_CONSUMER_KEY_UNKNOWN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_CONSUMER_KEY_REFUSED", OAUTH_CONSUMER_KEY_REFUSED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_INVALID_SIGNATURE", OAUTH_INVALID_SIGNATURE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_TOKEN_USED", OAUTH_TOKEN_USED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_TOKEN_EXPIRED", OAUTH_TOKEN_EXPIRED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_TOKEN_REVOKED", OAUTH_TOKEN_REVOKED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_TOKEN_REJECTED", OAUTH_TOKEN_REJECTED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_VERIFIER_INVALID", OAUTH_VERIFIER_INVALID, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_PARAMETER_ABSENT", OAUTH_PARAMETER_ABSENT, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OAUTH_SIGNATURE_METHOD_REJECTED", OAUTH_SIGNATURE_METHOD_REJECTED, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
*/
PHP_MSHUTDOWN_FUNCTION(oauth) 
{
	oauth_class_entry = NULL;
#if OAUTH_USE_CURL
	curl_global_cleanup();
#endif
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
*/
PHP_MINFO_FUNCTION(oauth) 
{
	php_info_print_table_start();
	php_info_print_table_header(2, "OAuth support", "enabled");
	php_info_print_table_row(2, "PLAINTEXT support", "enabled");
#if HAVE_OPENSSL_EXT 
	php_info_print_table_row(2, "RSA-SHA1 support", "enabled");
#else
	php_info_print_table_row(2, "RSA-SHA1 support", "not supported");
#endif
	php_info_print_table_row(2, "HMAC-SHA1 support", "enabled");
#if OAUTH_USE_CURL
	php_info_print_table_row(2, "Request engine support", "php_streams, curl");
#else
	php_info_print_table_row(2, "Request engine support", "php_streams");
#endif
	php_info_print_table_row(2, "source version", "$Id$");
	php_info_print_table_row(2, "version", OAUTH_EXT_VER);
	php_info_print_table_end();
}
/* }}} */

/* TODO expose a function for base sig string */
zend_function_entry oauth_global_functions[] = { /* {{{ */
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
ZEND_GET_MODULE(oauth)
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

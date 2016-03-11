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

static zend_class_entry *soo_class_entry;
static zend_class_entry *soo_exception_ce;
static zend_object_handlers so_object_handlers;

static zend_object* php_so_object_new(zend_class_entry *ce) /* {{{ */
{
	php_so_object *nos;

	nos = ecalloc(1, sizeof(php_so_object) + zend_object_properties_size(ce));
	nos->signature = NULL;
	nos->timeout = 0;

	zend_object_std_init(&nos->zo, ce);
	object_properties_init(&nos->zo, ce);

	nos->zo.handlers = &so_object_handlers;

	return &nos->zo;
}
/* }}} */

static zend_object *oauth_clone_obj(zval *this_ptr) /* {{{ */
{
	php_so_object *old_obj = Z_SOO_P(this_ptr);
	php_so_object *new_obj = so_object_from_obj(php_so_object_new(old_obj->zo.ce));

	zend_objects_clone_members(&new_obj->zo, &old_obj->zo);

	return &new_obj->zo;
}
/* }}} */

static int oauth_parse_str(char *params, zval *dest_array) /* {{{ */
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
		add_assoc_string(dest_array, var, val);
		efree(val);
		var = php_strtok_r(NULL, separator, &strtok_buf);
	}

	efree(separator);
	return SUCCESS;
}
/* }}} */

static int so_set_response_args(HashTable *hasht, zval *data, zval *retarray) /* {{{ */
{
	if (data && Z_TYPE_P(data) == IS_STRING) {

		if (retarray) {
			char *res = NULL;

			res = estrndup(Z_STRVAL_P(data), Z_STRLEN_P(data));
			/* do not use oauth_parse_str here, we want the result to pass through input filters */
			sapi_module.treat_data(PARSE_STRING, res, retarray);
		}

		return (zend_hash_str_update(hasht, OAUTH_RAW_LAST_RES, sizeof(OAUTH_RAW_LAST_RES) -1, data) == NULL) ? FAILURE : SUCCESS;
	}
	return FAILURE;
}
/* }}} */

static zval *so_set_response_info(HashTable *hasht, zval *info) /* {{{ */
{
	return zend_hash_str_update(hasht, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO) - 1, info);
}
/* }}} */

static void oauth_prop_hash_dtor(php_so_object *soo) /* {{{ */
{
	HashTable *ht;

	ht = soo->properties;

	FREE_ARGS_HASH(ht);
}
/* }}} */

static void so_object_free_storage(zend_object *obj) /* {{{ */
{
	php_so_object *soo;

	soo = so_object_from_obj(obj);
	zend_object_std_dtor(&soo->zo);

	if (soo->lastresponse.c) {
		smart_string_free(&soo->lastresponse);
	}
	if (soo->headers_in.c) {
		smart_string_free(&soo->headers_in);
	}
	if (soo->headers_out.c) {
		smart_string_free(&soo->headers_out);
	}
	if (soo->signature) {
		zend_string_release(soo->signature);
	}

	oauth_prop_hash_dtor(soo);

	if (soo->debug_info) {
		FREE_DEBUG_INFO(soo->debug_info);
		if (soo->debug_info->sbs) {
			efree(soo->debug_info->sbs);
		}
		efree(soo->debug_info);
		soo->debug_info = NULL;
	}

	smart_string_free(&soo->headers_in);
	if (soo->headers_out.c) {
		smart_string_free(&soo->headers_out);
	}
	if(Z_TYPE(soo->debugArr) != IS_UNDEF) {
		zval_ptr_dtor(&soo->debugArr);
	}
	OAUTH_SIGCTX_FREE(soo->sig_ctx);
	if (soo->nonce) {
		efree(soo->nonce);
	}
	if (soo->timestamp) {
		efree(soo->timestamp);
	}

}
/* }}} */

void soo_handle_error(php_so_object *soo, long errorCode, char *msg, char *response, char *additional_info) /* {{{ */
{
	zval ex;
	zend_class_entry *dex = zend_exception_get_default(), *soox = soo_exception_ce;

	object_init_ex(&ex, soox);

	if (!errorCode) {
		php_error(E_WARNING, "caller did not pass an errorcode!");
	} else {
		zend_update_property_long(dex, &ex, "code", sizeof("code")-1, errorCode);
	}
	if (response) {
		zend_update_property_string(dex, &ex, "lastResponse", sizeof("lastResponse")-1, response);
	}
	if(soo && soo->debug && Z_TYPE(soo->debugArr) != IS_UNDEF) {
		zend_update_property(dex, &ex, "debugInfo", sizeof("debugInfo") - 1, &soo->debugArr);
	}

	if(additional_info) {
		zend_update_property_string(dex, &ex, "additionalInfo", sizeof("additionalInfo")-1, additional_info);
	}

	zend_update_property_string(dex, &ex, "message", sizeof("message")-1, msg);
	zend_throw_exception_object(&ex);
}
/* }}} */


zend_string *soo_sign_hmac(php_so_object *soo, char *message, const char *cs, const char *ts, const oauth_sig_context *ctx) /* {{{ */
{
	zval args[4], retval, func;
	char *tret;
	zend_string *result;

	ZVAL_STRING(&func, "hash_hmac");

	if (!zend_is_callable(&func, 0, NULL)) {
		zval_ptr_dtor(&func);
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "HMAC signature generation failed, is ext/hash installed?", NULL, NULL);
		return NULL;
	}

	/* cs and ts would at best be empty, so this should be safe ;-) */
	spprintf(&tret, 0, "%s&%s", cs, ts);

	ZVAL_STRING(&args[0], ctx->hash_algo);
	ZVAL_STRING(&args[1], message);
	ZVAL_STRING(&args[2], tret);
	ZVAL_BOOL(&args[3], 1);

	call_user_function(EG(function_table), NULL, &func, &retval, 4, args);
	result = php_base64_encode((unsigned char *)Z_STRVAL(retval), Z_STRLEN(retval));

	efree(tret);
	zval_ptr_dtor(&retval);
	zval_ptr_dtor(&func);
	zval_ptr_dtor(&args[0]);
	zval_ptr_dtor(&args[1]);
	zval_ptr_dtor(&args[2]);
	zval_ptr_dtor(&args[3]);

	return result;
}
/* }}} */

zend_string *soo_sign_rsa(php_so_object *soo, char *message, const oauth_sig_context *ctx)
{
	zval args[3], func, retval;
	zend_string *result;

	/* check for empty private key */
	if (Z_TYPE(ctx->privatekey) == IS_UNDEF) {
		return NULL;
	}

	ZVAL_STRING(&func, "openssl_sign");

	/* TODO: add support for other algorithms instead of OPENSSL_ALGO_SHA1 */

	ZVAL_STRING(&args[0], message);
	ZVAL_DUP(&args[2], &ctx->privatekey);

	call_user_function_ex(EG(function_table), NULL, &func, &retval, 3, args, 0, NULL);

	if (Z_TYPE(retval) == IS_TRUE || Z_TYPE(retval) == IS_FALSE) {
		result = php_base64_encode((unsigned char *) Z_STRVAL_P(Z_REFVAL(args[1])), Z_STRLEN_P(Z_REFVAL(args[1])));
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

zend_string *soo_sign_plain(php_so_object *soo, const char *cs, const char *ts) /* {{{ */
{
	return strpprintf(0, "%s&%s", cs, ts);
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

zend_string *soo_sign(php_so_object *soo, char *message, zval *cs, zval *ts, const oauth_sig_context *ctx)
{
	const char *csec = cs?Z_STRVAL_P(cs):"", *tsec = ts?Z_STRVAL_P(ts):"";

	if (OAUTH_SIGCTX_TYPE_HMAC==ctx->type) {
		return soo_sign_hmac(soo, message, csec, tsec, ctx);
	} else if (OAUTH_SIGCTX_TYPE_RSA==ctx->type) {
		return soo_sign_rsa(soo, message, ctx);
	} else if(OAUTH_SIGCTX_TYPE_PLAIN==ctx->type) {
		return soo_sign_plain(soo, csec, tsec);
	}
	return NULL;
}

static inline zval *soo_get_property(php_so_object *soo, char *prop_name) /* {{{ */
{
	return zend_hash_str_find(soo->properties, prop_name, strlen(prop_name));
}
/* }}} */

/* XXX for auth type, need to make sure that the auth type is actually supported before setting */
static inline int soo_set_property(php_so_object *soo, zval *prop, char *prop_name) /* {{{ */
{
	return (zend_hash_str_update(soo->properties, prop_name, strlen(prop_name), prop) == NULL) ? FAILURE : SUCCESS;
}
/* }}} */

zend_string *oauth_url_encode(char *url, int url_len) /* {{{ */
{
	zend_string *urlencoded = NULL;
	zend_string *ret = NULL;

	if (url) {
		if (url_len < 0) {
			url_len = strlen(url);
		}
		urlencoded = php_raw_url_encode(url, url_len);
	}

	if (urlencoded) {
		ret = php_str_to_str(ZSTR_VAL(urlencoded), ZSTR_LEN(urlencoded), "%7E", sizeof("%7E")-1, "~", sizeof("~")-1);
		zend_string_free(urlencoded);
		return ret;
	}
	return NULL;
}
/* }}} */

zend_string *oauth_http_encode_value(zval *v)
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

static int oauth_strcmp(zval *first, zval *second)
{
	int result;
	result = string_compare_function(first, second);

	if (result < 0) {
		return -1;
	} else if (result > 0) {
		return 1;
	}

	return 0;
}

static int oauth_compare_value(const void *a, const void *b)
{
	Bucket *f, *s;
	f = *(Bucket **)a;
	s = *(Bucket **)b;

	return oauth_strcmp(&f->val, &s->val);
}

static int oauth_compare_key(const void *a, const void *b)
{
	zval first, second;
	int result;
    Bucket *f, *s;
	f = (Bucket *) a;
	s = (Bucket *) b;

	if (f->key == NULL) {
		ZVAL_LONG(&first, f->h);
	} else {
		ZVAL_STRINGL(&first, ZSTR_VAL(f->key), ZSTR_LEN(f->key));
	}

	if (s->key == NULL) {
		ZVAL_LONG(&second, s->h);
	} else {
		ZVAL_STRINGL(&second, ZSTR_VAL(s->key), ZSTR_LEN(s->key));
	}

	result = oauth_strcmp(&first, &second);
	zval_ptr_dtor(&first);
	zval_ptr_dtor(&second);
	return result;
}

/* build url-encoded string from args, optionally starting with & */
int oauth_http_build_query(php_so_object *soo, smart_string *s, HashTable *args, zend_bool prepend_amp)
{
	zval *cur_val;
	zend_string *cur_key, *arg_key, *param_value;
	int numargs = 0, hash_key_type, skip_append = 0, i, found;
	ulong num_index;
	HashPosition pos;
	smart_string keyname;

	smart_string_0(s);
	if (args) {
		if (soo && !soo->is_multipart) {
			for (zend_hash_internal_pointer_reset_ex(args, &pos);
				 HASH_KEY_NON_EXISTENT != (hash_key_type = zend_hash_get_current_key_ex(args, &cur_key, &num_index, &pos));
				 zend_hash_move_forward_ex(args, &pos)) {
				cur_val = zend_hash_get_current_data_ex(args, &pos);
				if (hash_key_type == HASH_KEY_IS_STRING &&
					*ZSTR_VAL(cur_key) =='@' && *Z_STRVAL_P(cur_val) =='@') {
					soo->is_multipart = 1;
					break;
				}
			}
		}

		for (zend_hash_internal_pointer_reset_ex(args, &pos);
				HASH_KEY_NON_EXISTENT != (hash_key_type = zend_hash_get_current_key_ex(args, &cur_key, &num_index, &pos));
				zend_hash_move_forward_ex(args, &pos)) {
			(cur_val = zend_hash_get_current_data_ex(args, &pos));

			skip_append = 0;

			switch (hash_key_type) {
				case HASH_KEY_IS_STRING:
					if (soo && soo->is_multipart && strncmp(ZSTR_VAL(cur_key), "oauth_", 6) != 0) {
						found = 0;
						for (i=0; i<soo->multipart_files_num; ++i) {
							if (0 == strcmp(soo->multipart_params[i], ZSTR_VAL(cur_key))) {
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
						soo->multipart_params[soo->multipart_files_num] = ZSTR_VAL(cur_key);

						++soo->multipart_files_num;
						/* we don't add multipart files to the params */
						skip_append = 1;
					} else {
						arg_key = oauth_url_encode(ZSTR_VAL(cur_key), ZSTR_LEN(cur_key));
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

			INIT_smart_string(keyname);
			if (arg_key) {
				smart_string_appends(&keyname, ZSTR_VAL(arg_key));
				zend_string_release(arg_key);
			} else {
				smart_string_append_unsigned(&keyname, num_index);
			}
			if (IS_ARRAY == Z_TYPE_P(cur_val)) {
				HashPosition val_pos;
				zval *val_cur_val;

				/* make shallow copy */
				SEPARATE_ZVAL(cur_val);
				/* sort array based on string comparison */
				zend_hash_sort(Z_ARRVAL_P(cur_val), oauth_compare_value, 1);

				/* traverse array */
				zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(cur_val), &val_pos);
				while ((val_cur_val = zend_hash_get_current_data_ex(Z_ARRVAL_P(cur_val), &val_pos)) != NULL) {
					if (prepend_amp) {
						smart_string_appendc(s, '&');
					}

					smart_string_append(s, &keyname);
					param_value = oauth_http_encode_value(val_cur_val);
					if (param_value) {
						smart_string_appendc(s, '=');
						smart_string_appends(s, ZSTR_VAL(param_value));
						zend_string_release(param_value);
					}
					prepend_amp = TRUE;
					++numargs;
					zend_hash_move_forward_ex(Z_ARRVAL_P(cur_val), &val_pos);
				}
				/* clean up */
			} else {
				if (prepend_amp) {
					smart_string_appendc(s, '&');
				}
				smart_string_append(s, &keyname);
				param_value = oauth_http_encode_value(cur_val);
				if (param_value) {
					smart_string_appendc(s, '=');
					smart_string_appends(s, ZSTR_VAL(param_value));
					zend_string_release(param_value);
				}
				prepend_amp = TRUE;
				++numargs;
			}
			smart_string_free(&keyname);

			smart_string_0(s);
		}
	}
	return numargs;
}

/* retrieves parameter value from the _GET or _POST superglobal */
void get_request_param(char *arg_name, char **return_val, int *return_len)
{
	zval *ptr;
	if (
	    (Z_TYPE(PG(http_globals)[TRACK_VARS_GET]) != IS_UNDEF && (ptr = zend_hash_str_find(HASH_OF(&(PG(http_globals)[TRACK_VARS_GET])), arg_name, strlen(arg_name)))  != NULL && IS_STRING == Z_TYPE_P(ptr)) ||
	    (Z_TYPE(PG(http_globals)[TRACK_VARS_POST])!= IS_UNDEF && (ptr = zend_hash_str_find(HASH_OF(&(PG(http_globals)[TRACK_VARS_POST])), arg_name, strlen(arg_name))) != NULL && IS_STRING == Z_TYPE_P(ptr))
	   ) {
		*return_val = Z_STRVAL_P(ptr);
		*return_len = Z_STRLEN_P(ptr);
		return;
	}
	*return_val = NULL;
	*return_len = 0;
}

/*
 * This function does not currently care to respect parameter precedence, in the sense that if a common param is defined
 * in POST/GET or Authorization header, the precendence is defined by: OAuth Core 1.0 section 9.1.1
 */

zend_string *oauth_generate_sig_base(php_so_object *soo, const char *http_method, const char *uri, HashTable *post_args, HashTable *extra_args) /* {{{ */
{
	zval params;
	char *query;
	char *s_port = NULL;
	zend_string *bufz = NULL;
	zend_string *sbs_query_part = NULL, *sbs_scheme_part = NULL;
	php_url *urlparts;
	smart_string sbuf = {0};

	urlparts = php_url_parse_ex(uri, strlen(uri));

	if (urlparts) {
		if (!urlparts->host || !urlparts->scheme) {
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid url when trying to build base signature string", NULL, NULL);
			php_url_free(urlparts);
			return NULL;
		}
		php_strtolower(urlparts->scheme, strlen(urlparts->scheme));
		php_strtolower(urlparts->host, strlen(urlparts->host));
		smart_string_appends(&sbuf, urlparts->scheme);
		smart_string_appends(&sbuf, "://");
		smart_string_appends(&sbuf, urlparts->host);

		if (urlparts->port && ((!strcmp("http", urlparts->scheme) && OAUTH_HTTP_PORT != urlparts->port)
					|| (!strcmp("https", urlparts->scheme) && OAUTH_HTTPS_PORT != urlparts->port))) {
			spprintf(&s_port, 0, "%d", urlparts->port);
			smart_string_appendc(&sbuf, ':');
			smart_string_appends(&sbuf, s_port);
			efree(s_port);
		}

		if (urlparts->path) {
			smart_string squery = {0};
			smart_string_appends(&sbuf, urlparts->path);
			smart_string_0(&sbuf);

			array_init(&params);

			/* merge order = oauth_args - extra_args - query */
			if (post_args) {
				zend_hash_merge(Z_ARRVAL(params), post_args, (copy_ctor_func_t) zval_add_ref, 0);
			}

			if (extra_args) {
				zend_hash_merge(Z_ARRVAL(params), extra_args, (copy_ctor_func_t) zval_add_ref, 0);
			}

			if (urlparts->query) {
				query = estrdup(urlparts->query);
				oauth_parse_str(query, &params);
				efree(query);
			}

			/* remove oauth_signature if it's in the hash */
			zend_hash_str_del(Z_ARRVAL(params), OAUTH_PARAM_SIGNATURE, sizeof(OAUTH_PARAM_SIGNATURE) - 1);

			/* exret2 = uksort(&exargs2[0], "strnatcmp") */
			zend_hash_sort(Z_ARRVAL(params), oauth_compare_key, 0);

			oauth_http_build_query(soo, &squery, Z_ARRVAL(params), FALSE);
			smart_string_0(&squery);
			zval_ptr_dtor(&params);

			sbs_query_part = oauth_url_encode(squery.c, squery.len);
			sbs_scheme_part = oauth_url_encode(sbuf.c, sbuf.len);

			bufz = strpprintf(0, "%s&%s&%s", http_method, ZSTR_VAL(sbs_scheme_part), sbs_query_part ? ZSTR_VAL(sbs_query_part) : "");
			/* TODO move this into oauth_get_http_method()
			   soo_handle_error(OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL);
			   */
			if(sbs_query_part) {
				zend_string_release(sbs_query_part);
			}
			if(sbs_scheme_part) {
				zend_string_release(sbs_scheme_part);
			}
			smart_string_free(&squery);
		} else {
			/* Bug 22630 - throw exception if no path given */
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid path (perhaps you only specified the hostname? try adding a slash at the end)", NULL, NULL);
			return NULL;
		}

		smart_string_free(&sbuf);

		php_url_free(urlparts);

		if(soo && soo->debug) {
			if(soo->debug_info->sbs) {
				zend_string_release(soo->debug_info->sbs);
			}

			if (bufz) {
				soo->debug_info->sbs = bufz;
				zend_string_addref(soo->debug_info->sbs);
			} else {
				soo->debug_info->sbs = NULL;
			}
		}
		return bufz;
	}
	return NULL;
}
/* }}} */

static void oauth_set_debug_info(php_so_object *soo) {
	zval *debugInfo;
	if (soo->debug_info) {
		debugInfo = &soo->debugArr;

		if (Z_TYPE_P(debugInfo) != IS_UNDEF) {
			zval_ptr_dtor(debugInfo);
		}
		array_init(debugInfo);

		if(soo->debug_info->sbs) {
			add_assoc_string(debugInfo, "sbs", ZSTR_VAL(soo->debug_info->sbs));
		}

		ADD_DEBUG_INFO(debugInfo, "headers_sent", soo->debug_info->headers_out, 1);
		ADD_DEBUG_INFO(debugInfo, "headers_recv", soo->headers_in, 1);
		ADD_DEBUG_INFO(debugInfo, "body_sent", soo->debug_info->body_out, 0);
		ADD_DEBUG_INFO(debugInfo, "body_recv", soo->debug_info->body_in, 0);
		ADD_DEBUG_INFO(debugInfo, "info", soo->debug_info->curl_info, 0);

		zend_update_property(soo_class_entry, soo->this_ptr, "debugInfo", sizeof("debugInfo") - 1, debugInfo);
	} else {
		ZVAL_UNDEF(&soo->debugArr);
	}
}

static int add_arg_for_req(HashTable *ht, const char *arg, const char *val) /* {{{ */
{
	zval varg;

	ZVAL_STRING(&varg, (char *)val);
	zend_hash_str_update(ht, (char *)arg, strlen(arg), &varg);

	return SUCCESS;
}
/* }}} */

void oauth_add_signature_header(HashTable *request_headers, HashTable *oauth_args, smart_string *header)
{
	smart_string sheader = {0};
	zend_bool prepend_comma = FALSE;

	zval *curval;
	zend_string *param_name, *param_val;
	zend_string *cur_key;
	ulong num_key;

	smart_string_appends(&sheader, "OAuth ");

	for (zend_hash_internal_pointer_reset(oauth_args);
			(curval = zend_hash_get_current_data(oauth_args)) != NULL;
			zend_hash_move_forward(oauth_args)) {
		zend_hash_get_current_key(oauth_args, &cur_key, &num_key);

		if (prepend_comma) {
			smart_string_appendc(&sheader, ',');
		}
		param_name = oauth_url_encode(ZSTR_VAL(cur_key), ZSTR_LEN(cur_key));
		param_val = oauth_url_encode(Z_STRVAL_P(curval), Z_STRLEN_P(curval));

		smart_string_appends(&sheader, ZSTR_VAL(param_name));
		smart_string_appendc(&sheader, '=');
		smart_string_appends(&sheader, "\"");
		smart_string_appends(&sheader, ZSTR_VAL(param_val));
		smart_string_appends(&sheader, "\"");

		efree(param_name);
		efree(param_val);
		prepend_comma = TRUE;
	}
	smart_string_0(&sheader);

	if (!header) {
		add_arg_for_req(request_headers, "Authorization", sheader.c);
	} else {
		smart_string_appends(header, sheader.c);
	}
	smart_string_free(&sheader);
}

#define HTTP_RESPONSE_CAAS(zvalp, header, storkey) { \
	if (0==strncasecmp(Z_STRVAL_P(zvalp),header,sizeof(header)-1)) { \
		CAAS(storkey, (Z_STRVAL_P(zvalp)+sizeof(header)-1)); \
	} \
}

#define HTTP_RESPONSE_CAAD(zvalp, header, storkey) { \
	if (0==strncasecmp(Z_STRVAL_P(zvalp),header,sizeof(header)-1)) { \
		CAAD(storkey, strtoul(Z_STRVAL_P(zvalp)+sizeof(header)-1,NULL,10)); \
	} \
}

#define HTTP_RESPONSE_CODE(zvalp) \
	if (response_code < 0 && 0==strncasecmp(Z_STRVAL_P(zvalp),"HTTP/", 5) && Z_STRLEN_P(zvalp)>=12) { \
		response_code = strtol(Z_STRVAL_P(zvalp)+9, NULL, 10); \
		CAAL("http_code", response_code); \
	}

#define HTTP_RESPONSE_LOCATION(zvalp) \
	if (0==strncasecmp(Z_STRVAL_P(zvalp), "Location: ", 10)) { \
		strlcpy(soo->last_location_header, Z_STRVAL_P(zvalp)+10, OAUTH_MAX_HEADER_LEN); \
	}

static long make_req_streams(php_so_object *soo, const char *url, const smart_string *payload, const char *http_method, HashTable *request_headers) /* {{{ */
{
	php_stream_context *sc;
	zval zpayload, zmethod, zredirects, zerrign;
	long response_code = -1;
	php_stream *s;
	int set_form_content_type = 0;
	php_netstream_data_t *sock;
	struct timeval tv;
	int secs = 0;

	sc = php_stream_context_alloc();

	if (payload->len) {
		smart_string_0(payload);
		ZVAL_STRINGL(&zpayload, payload->c, payload->len);
		php_stream_context_set_option(sc, "http", "content", &zpayload);
		zval_ptr_dtor(&zpayload);
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
		smart_string sheaders = {0};
		int first = 1;

		for (zend_hash_internal_pointer_reset(request_headers);
				(cur_val = zend_hash_get_current_data(request_headers)) != NULL;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key is used */
			smart_string sheaderline = {0};
			switch (zend_hash_get_current_key(request_headers, &cur_key, &num_key)) {
				case HASH_KEY_IS_STRING:
					smart_string_appendl(&sheaderline, ZSTR_VAL(cur_key), ZSTR_LEN(cur_key));
					break;
				default:
					continue;
			}
			smart_string_0(&sheaderline);
			if (!strcasecmp(sheaderline.c,"content-type")) {
				set_form_content_type = 0;
			}
			smart_string_appends(&sheaderline, ": ");
			switch (Z_TYPE_P(cur_val)) {
				case IS_STRING:
					smart_string_appendl(&sheaderline, Z_STRVAL_P(cur_val), Z_STRLEN_P(cur_val));
					break;
				default:
					smart_string_free(&sheaderline);
					continue;
			}
			if (!first) {
				smart_string_appends(&sheaders, "\r\n");
			} else {
				first = 0;
			}
			smart_string_append(&sheaders, &sheaderline);
			smart_string_free(&sheaderline);
		}
		if (set_form_content_type) {
			/* still need to add our own content-type? */
			if (!first) {
				smart_string_appends(&sheaders, "\r\n");
			}
			smart_string_appends(&sheaders, "Content-Type: application/x-www-form-urlencoded");
		}
		if (sheaders.len) {
			smart_string_0(&sheaders);
			ZVAL_STRINGL(&zheaders, sheaders.c, sheaders.len);
			php_stream_context_set_option(sc, "http", "header", &zheaders);
			zval_ptr_dtor(&zheaders);
			if (soo->debug) {
				smart_string_append(&soo->debug_info->headers_out, &sheaders);
			}
		}
		smart_string_free(&sheaders);
	}
	/* set method */
	ZVAL_STRING(&zmethod, http_method);
	php_stream_context_set_option(sc, "http", "method", &zmethod);
	zval_ptr_dtor(&zmethod);
	/* set maximum redirects; who came up with the ridiculous logic of <= 1 means no redirects ?? */
	ZVAL_LONG(&zredirects, 1L);
	php_stream_context_set_option(sc, "http", "max_redirects", &zredirects);
	/* using special extension to treat redirects as regular document (requires patch in php) */
	ZVAL_BOOL(&zerrign, TRUE);
	php_stream_context_set_option(sc, "http", "ignore_errors", &zerrign);

	smart_string_free(&soo->lastresponse);
	smart_string_free(&soo->headers_in);

	if ((s = php_stream_open_wrapper_ex((char*)url, "rb", REPORT_ERRORS, NULL, sc))) {
		zval info;
		zend_string *buf;
		size_t rb = 0;

		array_init(&info);

		CAAS("url", url);

		if (Z_TYPE(s->wrapperdata) != IS_UNDEF) {
			zval *tmp;

			zend_hash_internal_pointer_reset(Z_ARRVAL(s->wrapperdata));
			while ((tmp = zend_hash_get_current_data(Z_ARRVAL(s->wrapperdata))) != NULL) {
				smart_string_appendl(&soo->headers_in, Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				smart_string_appends(&soo->headers_in, "\r\n");
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
			smart_string_appendl(&soo->lastresponse, ZSTR_VAL(buf), ZSTR_LEN(buf));
			rb = ZSTR_LEN(buf);
			zend_string_release(buf);
		}
		smart_string_0(&soo->lastresponse);
		smart_string_0(&soo->headers_in);

		CAAD("size_download", rb);
		CAAD("size_upload", payload->len);

		so_set_response_info(soo->properties, &info);

		php_stream_close(s);
	} else {
		char *bufz;

		spprintf(&bufz, 0, "making the request failed (%s)", "dunno why");
		soo_handle_error(soo, -1, bufz, soo->lastresponse.c, NULL);
		efree(bufz);
	}

	if(soo->debug) {
		smart_string_append(&soo->debug_info->body_in, &soo->lastresponse);
		smart_string_append(&soo->debug_info->body_out, payload);
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
	smart_string_appendl(&soo->lastresponse, ptr, relsize);

	return relsize;
}
/* }}} */

int oauth_debug_handler(CURL *ch, curl_infotype type, char *data, size_t data_len, void *ctx) /* {{{ */
{
	php_so_debug *sdbg;
	char *z_data = NULL;
	smart_string *dest;

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
		smart_string_appends(dest, z_data);
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
		smart_string_appendl(&soo->headers_in, header, hlen);
	}
	return hlen;
}

long make_req_curl(php_so_object *soo, const char *url, const smart_string *payload, const char *http_method, HashTable *request_headers) /* {{{ */
{
	CURLcode cres, ctres, crres;
	CURL *curl;
	struct curl_slist *curl_headers = NULL;
	long l_code, response_code = -1;
	double d_code;
	zval info, *zca_info, *zca_path, *cur_val;
	char *s_code, *content_type = NULL, *bufz = NULL;
	uint sslcheck;
	ulong num_key;
	smart_string sheader = {0};
	zend_string *cur_key;

	zca_info = soo_get_property(soo, OAUTH_ATTR_CA_INFO);
	zca_path = soo_get_property(soo, OAUTH_ATTR_CA_PATH);
	sslcheck = soo->sslcheck;

	curl = curl_easy_init();

	if (request_headers) {
		for (zend_hash_internal_pointer_reset(request_headers);
				(cur_val = zend_hash_get_current_data(request_headers)) != NULL;
				zend_hash_move_forward(request_headers)) {
			/* check if a string based key is used */
			switch (zend_hash_get_current_key(request_headers, &cur_key, &num_key)) {
				case HASH_KEY_IS_STRING:
					smart_string_appendl(&sheader, ZSTR_VAL(cur_key), ZSTR_LEN(cur_key));
					break;
				default:
					continue;
			}
			smart_string_appends(&sheader, ": ");
			switch (Z_TYPE_P(cur_val)) {
				case IS_STRING:
					smart_string_appendl(&sheader, Z_STRVAL_P(cur_val), Z_STRLEN_P(cur_val));
					break;
				default:
					smart_string_free(&sheader);
					continue;
			}

			smart_string_0(&sheader);
			curl_headers = curl_slist_append(curl_headers, sheader.c);
			smart_string_free(&sheader);
		}
	}

	if(soo->is_multipart) {
		struct curl_httppost *ff = NULL;
		struct curl_httppost *lf = NULL;
		int i;

		for(i=0; i < soo->multipart_files_num; i++) {
			char *type, *filename, *postval;

			/* swiped from ext/curl/interface.c to help with consistency */
			postval = estrdup(soo->multipart_files[i]);

			if (postval[0] == '@' && soo->multipart_params[i][0] == '@') {
				/* :< (chomp) @ */
				++soo->multipart_params[i];
				++postval;

				if((type = (char *) php_memnstr(postval, ";type=", sizeof(";type=") - 1, postval + strlen(soo->multipart_files[i]) - 1))) {
					*type = '\0';
				}
				if((filename = (char *) php_memnstr(postval, ";filename=", sizeof(";filename=") - 1, postval + strlen(soo->multipart_files[i]) - 1))) {
					*filename = '\0';
				}

				/* open_basedir check */
				if(php_check_open_basedir(postval)) {
					char *em;
					spprintf(&em, 0, "failed to open file for multipart request: %s", postval);
					soo_handle_error(soo, -1, em, NULL, NULL);
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
	} else if (payload->len) {
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
		if(zca_path && Z_STRLEN_P(zca_path)) {
			curl_easy_setopt(curl, CURLOPT_CAPATH, Z_STRVAL_P(zca_path));
		}
		if(zca_info && Z_STRLEN_P(zca_info)) {
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

	smart_string_free(&soo->lastresponse);
	smart_string_free(&soo->headers_in);

	if(soo->debug) {
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, oauth_debug_handler);
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, soo->debug_info);
	}

	cres = curl_easy_perform(curl);

	smart_string_0(&soo->lastresponse);
	smart_string_0(&soo->headers_in);

	if (curl_headers) {
		curl_slist_free_all(curl_headers);
	}

	if (CURLE_OK == cres) {
		ctres = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (CURLE_OK == crres && ctres == CURLE_OK) {
			array_init(&info);

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

			CAAS("headers_recv", soo->headers_in.c);

			so_set_response_info(soo->properties, &info);
		}
	} else {
		spprintf(&bufz, 0, "making the request failed (%s)", curl_easy_strerror(cres));
		soo_handle_error(soo, -1, bufz, soo->lastresponse.c, NULL);
		efree(bufz);
	}
	curl_easy_cleanup(curl);
	return response_code;
}
/* }}} */
#endif

static void make_standard_query(HashTable *ht, php_so_object *soo) /* {{{ */
{
	char *ts, *nonce;

	if (soo->timestamp) {
		ts = estrdup(soo->timestamp);
	} else {
		time_t now = time(NULL);
		/* XXX allow caller to set timestamp, if none set, then default to "now" */
		spprintf(&ts, 0, "%d", (int)now);
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
		spprintf(&nonce, 0, "%ld%08x%05x%.8f", php_rand(), sec, usec, php_combined_lcg() * 10);
	}

	add_arg_for_req(ht, OAUTH_PARAM_CONSUMER_KEY, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_CONSUMER_KEY)));
	add_arg_for_req(ht, OAUTH_PARAM_SIGNATURE_METHOD, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_SIGMETHOD)));

	add_arg_for_req(ht, OAUTH_PARAM_NONCE, nonce);

	add_arg_for_req(ht, OAUTH_PARAM_TIMESTAMP, ts);
	add_arg_for_req(ht, OAUTH_PARAM_VERSION, Z_STRVAL_P(soo_get_property(soo, OAUTH_ATTR_OAUTH_VERSION)));

	efree(ts); efree(nonce);
}
/* }}} */

/*
Returns the default http method to use with the different auth types
*/
static const char *oauth_get_http_method(php_so_object *soo, const char *http_method) /* {{{ */
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
static smart_string *http_prepare_url_concat(smart_string *surl) /* {{{ */
{
	smart_string_0(surl);
	if (!strchr(surl->c, '?')) {
		smart_string_appendc(surl, '?');
	} else {
		smart_string_appendc(surl, '&');
	}
	return surl;
}
/* }}} */

/*
Modifies passed url based on the location header that was received in the response headers, depending on whether the redirection was relative or absolute
*/
static void oauth_apply_url_redirect(smart_string *surl, const char *location) /* {{{ */
{
	php_url *urlparts;

	/* determine whether location is relative */
	if ('/'==*location) {
		urlparts = php_url_parse_ex(surl->c, surl->len);

		/* rebuild url from scratch */
		smart_string_free(surl);
		if (urlparts->scheme) {
			smart_string_appends(surl, urlparts->scheme);
			smart_string_appends(surl, "://");
		}
		if (urlparts->host) {
			smart_string_appends(surl, urlparts->host);
		}
		if (urlparts->port) {
			smart_string_appendc(surl, ':');
			smart_string_append_unsigned(surl, urlparts->port);
		}
		smart_string_appends(surl, location);

		php_url_free(urlparts);
	} else {
		smart_string_free(surl);
		smart_string_appends(surl, location);
	}
}
/* }}} */

/*
Prepares the request elements to be used by make_req(); this should allow for supporting streams in the future
*/
static long oauth_fetch(php_so_object *soo, const char *url, const char *method, zval *request_params, zval *request_headers, HashTable *init_oauth_args, int fetch_flags) /* {{{ */
{
	char *bufz = NULL;
	zend_string *sbs = NULL, *sig;
	const char *final_http_method;
	zval *token = NULL, *cs;
	zval *ts = NULL, *token_secret = NULL;
	zval zret;
	HashTable *oauth_args = NULL;
	HashTable *rargs = NULL, *rheaders = NULL;
	long http_response_code, auth_type;
	smart_string surl = {0}, payload = {0}, postdata = {0};
	uint is_redirect = FALSE, follow_redirects = 0, need_to_free_rheaders = 0;

	auth_type = Z_LVAL_P(soo_get_property(soo, OAUTH_ATTR_AUTHMETHOD));
	if(fetch_flags & OAUTH_OVERRIDE_HTTP_METHOD) {
		final_http_method = method;
	} else {
		final_http_method = oauth_get_http_method(soo, method ? method : OAUTH_HTTP_METHOD_POST);

		if (OAUTH_AUTH_TYPE_FORM==auth_type && strcasecmp(final_http_method, OAUTH_HTTP_METHOD_POST)) {
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "auth type is set to HTTP POST with a non-POST http method, use setAuthType to put OAuth parameters somewhere else in the request", NULL, NULL);
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
			oauth_http_build_query(soo, &postdata, rargs, FALSE);
			break;
		case IS_STRING:
			smart_string_appendl(&postdata, Z_STRVAL_P(request_params), Z_STRLEN_P(request_params));
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
	smart_string_appends(&surl, url);

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
		make_standard_query(oauth_args, soo);

		/* use token where applicable */
		if (fetch_flags & OAUTH_FETCH_USETOKEN) {
			token = soo_get_property(soo, OAUTH_ATTR_TOKEN);
			if (token) {
				add_arg_for_req(oauth_args, OAUTH_PARAM_TOKEN, Z_STRVAL_P(token));
			}
		}

		/* generate sig base on the semi-final url */
		smart_string_0(&surl);
		sbs = oauth_generate_sig_base(soo, final_http_method, surl.c, oauth_args, rargs);
		if (!sbs) {
			FREE_ARGS_HASH(oauth_args);
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url, unable to generate signature base string", NULL, NULL);
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

		if(soo->signature) {
			zend_string_release(soo->signature);
		}
		/* sign the request */
		sig = soo_sign(soo, ZSTR_VAL(sbs), cs, ts, soo->sig_ctx);
		soo->signature = sig;
		zend_string_release(sbs);

		if(fetch_flags & OAUTH_FETCH_SIGONLY) {
			FREE_ARGS_HASH(oauth_args);
			smart_string_free(&surl);
			smart_string_free(&postdata);
			if(need_to_free_rheaders) {
				FREE_ARGS_HASH(rheaders);
			}
			return SUCCESS;
		}

		if (!sig) {
			FREE_ARGS_HASH(oauth_args);
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Signature generation failed", NULL, NULL);
			break;
		}

		/* and add signature to the oauth parameters */
		add_arg_for_req(oauth_args, OAUTH_PARAM_SIGNATURE, ZSTR_VAL(sig));

		if(fetch_flags & OAUTH_FETCH_HEADONLY) {
			INIT_smart_string(soo->headers_out);
			oauth_add_signature_header(rheaders, oauth_args, &soo->headers_out);
			smart_string_0(&payload);
			FREE_ARGS_HASH(oauth_args);
			smart_string_free(&surl);
			smart_string_free(&postdata);
			if(need_to_free_rheaders) {
				FREE_ARGS_HASH(rheaders);
			}
			return SUCCESS;
		}

		if (!strcmp(final_http_method, OAUTH_HTTP_METHOD_GET)) {
			/* GET request means to extend the url, but not for redirects obviously */
			if (!is_redirect && postdata.len) {
				smart_string_append(http_prepare_url_concat(&surl), &postdata);
			}
		} else {
			/* otherwise populate post data */
			smart_string_append(&payload, &postdata);
		}

		switch (auth_type) {
			case OAUTH_AUTH_TYPE_FORM:
				/* append/set post data with oauth parameters */
				oauth_http_build_query(soo, &payload, oauth_args, payload.len);
				smart_string_0(&payload);
				break;
			case OAUTH_AUTH_TYPE_URI:
				/* extend url request with oauth parameters */
				if (!is_redirect) {
					oauth_http_build_query(soo, http_prepare_url_concat(&surl), oauth_args, FALSE);
				}
				/* TODO look into merging oauth parameters if they occur in the current url */
				break;
			case OAUTH_AUTH_TYPE_AUTHORIZATION:
				/* add http header with oauth parameters */
				oauth_add_signature_header(rheaders, oauth_args, NULL);
				break;
		}

		/* finalize endpoint url */
		smart_string_0(&surl);

		if (soo->debug) {
			if(soo->debug_info->sbs) {
				FREE_DEBUG_INFO(soo->debug_info);
			}
			INIT_DEBUG_INFO(soo->debug_info);
		}

		switch (soo->reqengine) {
			case OAUTH_REQENGINE_STREAMS:
				http_response_code = make_req_streams(soo, surl.c, &payload, final_http_method, rheaders);
				break;
#if OAUTH_USE_CURL
			case OAUTH_REQENGINE_CURL:
				http_response_code = make_req_curl(soo, surl.c, &payload, final_http_method, rheaders);
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
			oauth_set_debug_info(soo);
		}

		FREE_ARGS_HASH(oauth_args);
		smart_string_free(&payload);

		if (is_redirect) {
			if (follow_redirects) {
				if (soo->redirects >= OAUTH_MAX_REDIRS) {
					spprintf(&bufz, 0, "max redirections exceeded (max: %ld last redirect url: %s)", OAUTH_MAX_REDIRS, soo->last_location_header);
					if (soo->lastresponse.len) {
						ZVAL_STRING(&zret, soo->lastresponse.c);
					} else {
						ZVAL_STRING(&zret, "");
					}
					so_set_response_args(soo->properties, &zret, NULL);
					soo_handle_error(soo, http_response_code, bufz, soo->lastresponse.c, NULL);
					efree(bufz);
					/* set http_response_code to error value */
					http_response_code = -1;
					break;
				} else {
					++soo->redirects;
					oauth_apply_url_redirect(&surl, soo->last_location_header);
					smart_string_0(&surl);
/* bug 22628; keep same method when following redirects
					final_http_method = OAUTH_HTTP_METHOD_GET;
*/
				}
			}
		} else if (http_response_code < 0) {
			/* exception would have been thrown already */
		} else if (http_response_code < 200 || http_response_code > 209) {
			spprintf(&bufz, 0, "Invalid auth/bad request (got a %ld, expected HTTP/1.1 20X or a redirect)", http_response_code);
			if(soo->lastresponse.c) {
				ZVAL_STRING(&zret, soo->lastresponse.c);
			} else {
				ZVAL_STRING(&zret, "");
			}
			so_set_response_args(soo->properties, &zret, NULL);
			soo_handle_error(soo, http_response_code, bufz, soo->lastresponse.c, NULL);
			efree(bufz);
			/* set http_response_code to error value */
			http_response_code = -1;
			break;
		} else {
			/* valid response, time to get out of this loop */
		}
	} while (is_redirect && follow_redirects);

	smart_string_free(&surl);
	smart_string_free(&postdata);
	if(need_to_free_rheaders) {
		FREE_ARGS_HASH(rheaders);
	}

	return http_response_code;
}
/* }}} */

SO_METHOD(setRSACertificate)
{
	char *key;
	size_t key_len;
	zval args[1], func, retval;

	php_so_object *soo;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len) == FAILURE) {
		return;
	}

	ZVAL_STRING(&func, "openssl_get_privatekey");

	ZVAL_STRINGL(&args[0], key, key_len);


	call_user_function(EG(function_table), NULL, &func, &retval, 1, args);

	zval_ptr_dtor(&args[0]);
	zval_ptr_dtor(&func);

	if (Z_TYPE(retval) == IS_RESOURCE) {
		OAUTH_SIGCTX_SET_PRIVATEKEY(soo->sig_ctx, retval);
		RETURN_TRUE;
	} else {
		zval_ptr_dtor(&retval);
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Could not parse RSA certificate", NULL, NULL);
		return;
	}
}

/* {{{ proto string oauth_urlencode(string uri)
   URI encoding according to RFC 3986, note: is not utf8 capable until the underlying phpapi is */
PHP_FUNCTION(oauth_urlencode)
{
	size_t uri_len;
	char *uri;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &uri, &uri_len) == FAILURE) {
		return;
	}

	if (uri_len < 1) {
		php_error_docref(NULL, E_WARNING, "Invalid uri length (0)");
		RETURN_FALSE;
	}
	RETURN_STR(oauth_url_encode(uri, uri_len));
}
/* }}} */

/* {{{ proto string oauth_get_sbs(string http_method, string uri, array parameters)
   Get a signature base string */
PHP_FUNCTION(oauth_get_sbs)
{
	char *uri, *http_method;
	zend_string *sbs;
	size_t uri_len, http_method_len;
	zval *req_params = NULL;
	HashTable *rparams = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|a", &http_method, &http_method_len, &uri, &uri_len, &req_params) == FAILURE) {
		return;
	}

	if (uri_len < 1) {
		php_error_docref(NULL, E_WARNING, "Invalid uri length (0)");
		RETURN_FALSE;
	}

	if (http_method_len < 1) {
		php_error_docref(NULL, E_WARNING, "Invalid http method length (0)");
		RETURN_FALSE;
	}

	if (req_params) {
		rparams = HASH_OF(req_params);
	}

	if ((sbs = oauth_generate_sig_base(NULL, http_method, uri, NULL, rparams))) {
		RETURN_STR(sbs);
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
	zend_long auth_method = 0;
	zval zck, zcs, zsm, zam, zver, *obj;
	size_t ck_len = 0, cs_len = 0, sig_method_len = 0;
	php_so_object *soo;

	obj = getThis();

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|sssl", &ck, &ck_len, &cs, &cs_len, &sig_method, &sig_method_len, &auth_method) == FAILURE) {
		return;
	}

	soo = Z_SOO_P(obj);

	if(ck_len == 0) {
		soo_handle_error(soo, -1, "The consumer key cannot be empty", NULL, NULL);
		return;
	}

	if(cs_len == 0) {
		soo_handle_error(soo, -1, "The consumer secret cannot be empty", NULL, NULL);
		return;
	}

	memset(soo->last_location_header, 0, OAUTH_MAX_HEADER_LEN);
	soo->redirects = 0;
	soo->debug = 0;
	soo->debug_info = emalloc(sizeof(php_so_debug));
	soo->debug_info->sbs = NULL;
	ZVAL_UNDEF(&soo->debugArr);

	soo->nonce = NULL;
	soo->timestamp = NULL;
	soo->sig_ctx = NULL;
	soo->signature = NULL;

	INIT_DEBUG_INFO(soo->debug_info);

	INIT_smart_string(soo->headers_in);

	/* set default class members */
	zend_update_property_null(soo_class_entry, obj, "debugInfo", sizeof("debugInfo") - 1);
	zend_update_property_bool(soo_class_entry, obj, "debug", sizeof("debug") - 1, soo->debug);
	zend_update_property_long(soo_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, soo->sslcheck);

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
	if (soo_set_property(soo, &zck, OAUTH_ATTR_CONSUMER_KEY) != SUCCESS) {
		return;
	}

	if (cs_len > 0) {
		ZVAL_STR(&zcs, oauth_url_encode(cs, cs_len));
	} else {
		ZVAL_EMPTY_STRING(&zcs);
	}
	if (soo_set_property(soo, &zcs, OAUTH_ATTR_CONSUMER_SECRET) != SUCCESS) {
		return;
	}

	ZVAL_STRING(&zsm, sig_method);
	if (soo_set_property(soo, &zsm, OAUTH_ATTR_SIGMETHOD) != SUCCESS) {
		return;
	}

	ZVAL_LONG(&zam, auth_method);
	if (soo_set_property(soo, &zam, OAUTH_ATTR_AUTHMETHOD) != SUCCESS) {
		return;
	}

	ZVAL_STRING(&zver, OAUTH_DEFAULT_VERSION);
	if (soo_set_property(soo, &zver, OAUTH_ATTR_OAUTH_VERSION) != SUCCESS) {
		return;
	}

	soo->debug = 0;
	soo->sslcheck = OAUTH_SSLCHECK_BOTH;
	soo->follow_redirects = 1;

	soo->lastresponse.c = NULL;
#if OAUTH_USE_CURL
	soo->reqengine = OAUTH_REQENGINE_CURL;
#else
	soo->reqengine = OAUTH_REQENGINE_STREAMS;
#endif
}
/* }}} */

void oauth_free_privatekey(zval *privatekey)
{
	zval func, retval;
	zval args[1];

	if (Z_TYPE_P(privatekey)==IS_RESOURCE) {
		ZVAL_STRING(&func, "openssl_freekey");
		ZVAL_DUP(&args[0], privatekey);

		call_user_function(EG(function_table), NULL, &func, &retval, 1, args);

		zval_ptr_dtor(&func);
		zval_ptr_dtor(&retval);
	}

	zval_ptr_dtor(privatekey);
}

/* {{{ proto array OAuth::setCAPath(string ca_path, string ca_info)
   Set the Certificate Authority information */
SO_METHOD(setCAPath)
{
	php_so_object *soo;
	char *ca_path, *ca_info;
	size_t ca_path_len = 0, ca_info_len = 0;
	zval zca_path, zca_info;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|ss", &ca_path, &ca_path_len, &ca_info, &ca_info_len) == FAILURE) {
		return;
	}

	if (ca_path_len) {
		ZVAL_STRINGL(&zca_path, ca_path, ca_path_len);
		if (soo_set_property(soo, &zca_path, OAUTH_ATTR_CA_PATH) != SUCCESS) {
			RETURN_FALSE;
		}
	}

	if (ca_info_len) {
		ZVAL_STRINGL(&zca_info, ca_info, ca_info_len);
		if (soo_set_property(soo, &zca_info, OAUTH_ATTR_CA_INFO) != SUCCESS) {
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

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
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

/* {{{ proto array OAuth::getRequestToken(string request_token_url [, string callback_url [, http_method ] ])
   Get request token */
SO_METHOD(getRequestToken)
{
	php_so_object *soo;
	zval zret, *callback_url = NULL;
	char *url, *http_method = OAUTH_HTTP_METHOD_POST;
	size_t url_len = 0, http_method_len = sizeof(OAUTH_HTTP_METHOD_POST) - 1;
	long retcode;
	HashTable *args = NULL;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|zs", &url, &url_len, &callback_url, &http_method, &http_method_len) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid request token url length", NULL, NULL);
		RETURN_FALSE;
	}

	if (callback_url && IS_STRING==Z_TYPE_P(callback_url)) {
		ALLOC_HASHTABLE(args);
		zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
		if (Z_STRLEN_P(callback_url) > 0) {
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, Z_STRVAL_P(callback_url));
		} else {
			/* empty callback url specified, treat as 1.0a */
			add_arg_for_req(args, OAUTH_PARAM_CALLBACK, OAUTH_CALLBACK_OOB);
		}
	}

	retcode = oauth_fetch(soo, url, oauth_get_http_method(soo, http_method), NULL, NULL, args, 0);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.c) {
		array_init(return_value);
		ZVAL_STRINGL(&zret, soo->lastresponse.c, soo->lastresponse.len);
		so_set_response_args(soo->properties, &zret, return_value);
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

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
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

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
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
	soo = Z_SOO_P(obj);

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo->debug = 0;
	zend_update_property_bool(soo_class_entry, obj, "debug", sizeof("debug") - 1, 0);

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
	soo = Z_SOO_P(obj);

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo->debug = 1;
	zend_update_property_bool(soo_class_entry, obj, "debug", sizeof("debug") - 1, 1);

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
	soo = Z_SOO_P(obj);

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo->sslcheck = OAUTH_SSLCHECK_BOTH;
	zend_update_property_long(soo_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, 1);

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
	soo = Z_SOO_P(obj);

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo->sslcheck = OAUTH_SSLCHECK_NONE;
	zend_update_property_long(soo_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1, 0);

	RETURN_TRUE;
}
/* }}} */


/* {{{ proto bool OAuth::setSSLChecks(long sslcheck)
   Tweak specific SSL checks for requests (be careful using this for production) */
SO_METHOD(setSSLChecks)
{
	php_so_object *soo;
	zval *obj;
	zend_long sslcheck = OAUTH_SSLCHECK_BOTH;

	obj = getThis();
	soo = Z_SOO_P(obj);

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &sslcheck) == FAILURE) {
		return;
	}

	soo->sslcheck = sslcheck & OAUTH_SSLCHECK_BOTH;

	zend_update_property_long(soo_class_entry, obj, "sslChecks", sizeof("sslChecks") - 1,
			soo->sslcheck);

	RETURN_TRUE;
}
/* }}} */


/* {{{ proto bool OAuth::setVersion(string version)
   Set oauth_version for requests (default 1.0) */
SO_METHOD(setVersion)
{
	php_so_object *soo;
	size_t ver_len = 0;
	char *vers;
	zval zver;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &vers, &ver_len) == FAILURE) {
		return;
	}

	if (ver_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid version", NULL, NULL);
		RETURN_FALSE;
	}

	ZVAL_STRING(&zver, vers);
	if (SUCCESS == soo_set_property(soo, &zver, OAUTH_ATTR_OAUTH_VERSION)) {
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
	zend_long auth;
	zval zauth;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &auth) == FAILURE) {
		return;
	}

	switch (auth) {
		case OAUTH_AUTH_TYPE_URI:
		case OAUTH_AUTH_TYPE_FORM:
		case OAUTH_AUTH_TYPE_AUTHORIZATION:
		case OAUTH_AUTH_TYPE_NONE:
			ZVAL_LONG(&zauth, auth);
			if (SUCCESS == soo_set_property(soo, &zauth, OAUTH_ATTR_AUTHMETHOD)) {
				RETURN_TRUE;
			}
		default:
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid auth type", NULL, NULL);
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
	zend_long timeout;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &timeout) == FAILURE) {
		return;
	}

	if (timeout < 0) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid timeout", NULL, NULL);
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
	size_t nonce_len;
	char *nonce;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &nonce, &nonce_len) == FAILURE) {
		return;
	}

	if (nonce_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid nonce", NULL, NULL);
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
	size_t ts_len;
	char *ts;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &ts, &ts_len) == FAILURE) {
		return;
	}

	if (ts_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid timestamp", NULL, NULL);
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
	size_t token_len, token_secret_len;
	char *token, *token_secret;
	zval t,ts;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &token, &token_len, &token_secret, &token_secret_len) == FAILURE) {
		return;
	}

	ZVAL_STRING(&t, token);
	soo_set_property(soo, &t, OAUTH_ATTR_TOKEN);

	if (token_secret_len > 1) {
		ZVAL_STR(&ts, oauth_url_encode(token_secret, token_secret_len));
		soo_set_property(soo, &ts, OAUTH_ATTR_TOKEN_SECRET);
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto void OAuth::setRequestEngine(long reqengine) */
SO_METHOD(setRequestEngine)
{
	php_so_object *soo;
	zend_long reqengine;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &reqengine) == FAILURE) {
		return;
	}
	soo = Z_SOO_P(getThis());

	switch (reqengine) {
		case OAUTH_REQENGINE_STREAMS:
#if OAUTH_USE_CURL
		case OAUTH_REQENGINE_CURL:
#endif
			soo->reqengine = reqengine;
			break;
		default:
			soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid request engine specified", NULL, NULL);
	}
}
/* }}} */

/* {{{ proto bool OAuth::generateSignature(string http_method, string url [, string|array extra_parameters ])
   Generate a signature based on the final HTTP method, URL and a string/array of parameters */
SO_METHOD(generateSignature)
{
	php_so_object *soo;
	size_t url_len, http_method_len = 0;
	char *url;
	zval *request_args = NULL;
	char *http_method = NULL;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &http_method, &http_method_len, &url, &url_len, &request_args) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		RETURN_BOOL(FALSE);
	}

	if (oauth_fetch(soo, url, http_method, request_args, NULL, NULL, (OAUTH_FETCH_USETOKEN | OAUTH_FETCH_SIGONLY)) < 0) {
		RETURN_BOOL(FALSE);
	} else {
		zend_string_addref(soo->signature);
		RETURN_STR(soo->signature);
	}
}
/* }}} */

/* {{{ proto bool OAuth::fetch(string protected_resource_url [, string|array extra_parameters [, string request_type [, array request_headers]]])
   fetch a protected resource, pass in extra_parameters (array(name => value) or "custom body") */
SO_METHOD(fetch)
{
	php_so_object *soo;
	size_t fetchurl_len, http_method_len = 0;
	char *fetchurl;
	zval zret, *request_args = NULL, *request_headers = NULL;
	char *http_method = NULL;
	long retcode;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|zsa", &fetchurl, &fetchurl_len, &request_args, &http_method, &http_method_len, &request_headers) == FAILURE) {
		return;
	}

	if (fetchurl_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid protected resource url length", NULL, NULL);
		RETURN_FALSE;
	}

	retcode = oauth_fetch(soo, fetchurl, http_method, request_args, request_headers, NULL, OAUTH_FETCH_USETOKEN | OAUTH_OVERRIDE_HTTP_METHOD);

	ZVAL_STRINGL(&zret, soo->lastresponse.c, soo->lastresponse.len);
	so_set_response_args(soo->properties, &zret, NULL);

	if ((retcode < 200 || retcode > 206)) {
		RETURN_FALSE;
	} else {
		RETURN_BOOL(TRUE);
	}
}
/* }}} */

/* {{{ proto array OAuth::getAccessToken(string access_token_url [, string auth_session_handle [, string auth_verifier [, http_method ]]])
	Get access token,
	If the server supports Scalable OAuth pass in the auth_session_handle to refresh the token (http://wiki.oauth.net/ScalableOAuth)
	For 1.0a implementation, a verifier token must be passed; this token is not passed unless a value is explicitly assigned via the function arguments or $_GET/$_POST['oauth_verifier'] is set
*/
SO_METHOD(getAccessToken)
{
	php_so_object *soo;
	size_t aturi_len = 0, ash_len = 0, verifier_len_size_t = 0, http_method_len = sizeof(OAUTH_HTTP_METHOD_POST) - 1;
	int verifier_len;
	char *aturi, *ash, *verifier, *http_method = OAUTH_HTTP_METHOD_POST;
	zval zret;
	HashTable *args = NULL;
	long retcode;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|sss", &aturi, &aturi_len, &ash, &ash_len, &verifier, &verifier_len_size_t, &http_method, &http_method_len) == FAILURE) {
		return;
	}
	verifier_len = verifier_len_size_t;

	if (aturi_len < 1) {
		soo_handle_error(soo, OAUTH_ERR_INTERNAL_ERROR, "Invalid access token url length", NULL, NULL);
		RETURN_FALSE;
	}

	if (!verifier_len) {
		/* try to get from _GET/_POST */
		get_request_param(OAUTH_PARAM_VERIFIER, &verifier, &verifier_len);
	}

	if (ash_len > 0 || verifier_len > 0) {
		ALLOC_HASHTABLE(args);
		zend_hash_init(args, 0, NULL, ZVAL_PTR_DTOR, 0);
		if (ash_len > 0) {
			add_arg_for_req(args, OAUTH_PARAM_ASH, ash);
		}
		if (verifier_len > 0) {
			add_arg_for_req(args, OAUTH_PARAM_VERIFIER, verifier);
		}
	}

	retcode = oauth_fetch(soo, aturi, oauth_get_http_method(soo, http_method), NULL, NULL, args, OAUTH_FETCH_USETOKEN);

	if (args) {
		FREE_ARGS_HASH(args);
	}

	if (retcode != -1 && soo->lastresponse.c) {
		array_init(return_value);
		ZVAL_STRINGL(&zret, soo->lastresponse.c, soo->lastresponse.len);
		so_set_response_args(soo->properties, &zret, return_value);
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

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo = Z_SOO_P(getThis());

	if ((data_ptr = zend_hash_str_find(soo->properties, OAUTH_ATTR_LAST_RES_INFO, sizeof(OAUTH_ATTR_LAST_RES_INFO) - 1)) != NULL) {
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

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") == FAILURE) {
		return;
	}

	soo = Z_SOO_P(getThis());

	if (soo->lastresponse.c) {
		RETURN_STRINGL(soo->lastresponse.c, soo->lastresponse.len);
	}
}
/* }}} */

SO_METHOD(getLastResponseHeaders)
{
	php_so_object *soo;

	if (FAILURE==zend_parse_parameters(ZEND_NUM_ARGS(), "")) {
		return;
	}

	soo = Z_SOO_P(getThis());
	if (soo->headers_in.c) {
		RETURN_STRINGL(soo->headers_in.c, soo->headers_in.len);
	}
	RETURN_FALSE;
}

/* {{{ proto string OAuth::getRequestHeader(string http_method, string url [, string|array extra_parameters ])
   Generate OAuth header string signature based on the final HTTP method, URL and a string/array of parameters */
SO_METHOD(getRequestHeader)
{
	php_so_object *soo;
	size_t url_len, http_method_len = 0;
	char *url;
	zval *request_args = NULL;
	char *http_method = NULL;

	soo = Z_SOO_P(getThis());

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss|z", &http_method, &http_method_len, &url, &url_len, &request_args) == FAILURE) {
		return;
	}

	if (url_len < 1) {
		RETURN_BOOL(FALSE);
	}

	if (oauth_fetch(soo, url, http_method, request_args, NULL, NULL,
				(OAUTH_FETCH_USETOKEN | OAUTH_FETCH_HEADONLY)) < 0) {
		RETURN_BOOL(FALSE);
	} else {
		RETURN_STRINGL(soo->headers_out.c, soo->headers_out.len);
	}

	RETURN_FALSE;
}

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_urlencode, 0, 0, 1)
	ZEND_ARG_INFO(0, uri)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_sbs, 0, 0, 3)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, uri)
	ZEND_ARG_INFO(0, parameters)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth__construct, 0, 0, 2)
	ZEND_ARG_INFO(0, consumer_key)
	ZEND_ARG_INFO(0, consumer_secret)
	ZEND_ARG_INFO(0, signature_method)
	ZEND_ARG_INFO(0, auth_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getrequesttoken, 0, 0, 1)
	ZEND_ARG_INFO(0, request_token_url)
	ZEND_ARG_INFO(0, callback_url)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setversion, 0, 0, 1)
	ZEND_ARG_INFO(0, version)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setauthtype, 0, 0, 1)
	ZEND_ARG_INFO(0, auth_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setnonce, 0, 0, 1)
	ZEND_ARG_INFO(0, nonce)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settimestamp, 0, 0, 1)
	ZEND_ARG_INFO(0, ts)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settimeout, 0, 0, 1)
	ZEND_ARG_INFO(0, timeout_in_milliseconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setcapath, 0, 0, 2)
	ZEND_ARG_INFO(0, ca_path)
	ZEND_ARG_INFO(0, ca_info)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_settoken, 0, 0, 2)
	ZEND_ARG_INFO(0, token)
	ZEND_ARG_INFO(0, token_secret)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setrequestengine, 0, 0, 1)
	ZEND_ARG_INFO(0, reqengine)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_fetch, 0, 0, 1)
	ZEND_ARG_INFO(0, protected_resource_url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, request_headers)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getaccesstoken, 0, 0, 1)
	ZEND_ARG_INFO(0, access_token_url)
	ZEND_ARG_INFO(0, auth_session_handle)
	ZEND_ARG_INFO(0, auth_verifier)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setrsacertificate, 0, 0, 1)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_gensig, 0, 0, 2)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_setsslchecks, 0, 0, 1)
	ZEND_ARG_INFO(0, sslcheck)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getrequestheader, 0, 0, 2)
	ZEND_ARG_INFO(0, http_method)
	ZEND_ARG_INFO(0, url)
	ZEND_ARG_INFO(0, extra_parameters) /* ARRAY_INFO(1, arg, 0) */
ZEND_END_ARG_INFO()


/* }}} */


static zend_function_entry so_functions[] = { /* {{{ */
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
	{NULL, NULL, NULL}
};
/* }}} */


zval *oauth_read_member(zval *obj, zval *mem, int type, void **cache_slot, zval *rv) /* {{{ */
{
	zval *return_value = NULL;
	php_so_object *soo;

	soo = Z_SOO_P(obj);

	return_value = std_object_handlers.read_property(obj, mem, type, cache_slot, rv);

	if(!strcasecmp(Z_STRVAL_P(mem),"debug")) {
		convert_to_boolean(return_value);
		ZVAL_BOOL(return_value, soo->debug);
	} else if(!strcasecmp(Z_STRVAL_P(mem),"sslChecks")) {
		ZVAL_LONG(return_value, soo->sslcheck);
	}
	return return_value;
} /* }}} */

static void oauth_write_member(zval *obj, zval *mem, zval *value, void **cache_slot) /* {{{ */
{
	char *property;
	php_so_object *soo;

	property = Z_STRVAL_P(mem);
	soo = Z_SOO_P(obj);

	if(!strcmp(property,"debug")) {
		soo->debug = Z_TYPE_P(value) == IS_TRUE ? 1 : 0;
	} else if(!strcmp(property,"sslChecks")) {
		soo->sslcheck = Z_LVAL_P(value);
	}
	std_object_handlers.write_property(obj, mem, value, cache_slot);
} /* }}} */

/* {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION(oauth)
{
	zend_class_entry soce, soo_ex_ce;

#if OAUTH_USE_CURL
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		return FAILURE;
	}
#endif

	INIT_CLASS_ENTRY(soce, "OAuth", so_functions);
	soce.create_object = php_so_object_new;

	soo_class_entry = zend_register_internal_class(&soce);
	memcpy(&so_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	so_object_handlers.offset = XtOffsetOf(php_so_object, zo);

	so_object_handlers.read_property = oauth_read_member;
	so_object_handlers.write_property = oauth_write_member;
	so_object_handlers.clone_obj = oauth_clone_obj;
	so_object_handlers.free_obj = so_object_free_storage;


	zend_declare_property_long(soo_class_entry, "debug", sizeof("debug")-1, 0, ZEND_ACC_PUBLIC);
	zend_declare_property_long(soo_class_entry, "sslChecks", sizeof("sslChecks")-1, 1, ZEND_ACC_PUBLIC);
	zend_declare_property_string(soo_class_entry, "debugInfo", sizeof("debugInfo")-1, "", ZEND_ACC_PUBLIC);

	INIT_CLASS_ENTRY(soo_ex_ce, "OAuthException", NULL);

	soo_exception_ce = zend_register_internal_class_ex(&soo_ex_ce, zend_exception_get_default());
	zend_declare_property_null(soo_exception_ce, "lastResponse", sizeof("lastResponse")-1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(soo_exception_ce, "debugInfo", sizeof("debugInfo")-1, ZEND_ACC_PUBLIC);

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

	oauth_provider_register_class();
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
	soo_class_entry = NULL;
	soo_exception_ce = NULL;
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

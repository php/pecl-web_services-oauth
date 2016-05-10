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
/* $Id: oauth.c,v 1.60 2009/05/16 15:46:09 jawed Exp $ */

#include "php_oauth.h"
#include "provider.h"

#if PHP_WIN32
# include <windows.h>
# include <Wincrypt.h>
#endif

#include "fcntl.h"

static zend_object_handlers oauth_provider_obj_hndlrs;
static zend_class_entry *oauthprovider;

static inline void oauth_provider_set_param_member(zval *provider_obj, char *prop_name, zval *prop) /* {{{ */
{
	zend_update_property(Z_OBJCE_P(provider_obj), provider_obj, prop_name, strlen(prop_name), prop);
}
/* }}} */

static inline php_oauth_provider *fetch_sop_object(zval *obj) /* {{{ */
{
	php_oauth_provider *sop = Z_SOP_P(obj);
	sop->this_ptr = obj;
	return sop;
}
/* }}} */

static int oauth_provider_set_default_required_params(HashTable *ht) /* {{{ */
{
	char *required_params[] = {"oauth_consumer_key", "oauth_signature", "oauth_signature_method", "oauth_nonce", "oauth_timestamp", "oauth_token", NULL};
	unsigned int idx = 0;

	do {
		zval tmp;
		ZVAL_NULL(&tmp);
		if(zend_hash_str_add(ht, required_params[idx], strlen(required_params[idx]), &tmp) == NULL) {
			return FAILURE;
		}
		++idx;
	} while(required_params[idx]);

	return SUCCESS;
}
/* }}} */

static int oauth_provider_remove_required_param(HashTable *ht, char *required_param) /* {{{ */
{
	zval *dest_entry;
	zend_string *key;
	ulong num_key;
	HashPosition hpos;

	if((dest_entry = zend_hash_str_find(ht, required_param, strlen(required_param))) == NULL) {
		return FAILURE;
	} else {
		zend_hash_internal_pointer_reset_ex(ht, &hpos);
		do {
			if(zend_hash_get_current_key_ex(ht, &key, &num_key, &hpos)!=FAILURE) {
				if(!strcmp(ZSTR_VAL(key), required_param)) {
					zend_hash_del(ht, key);
					return SUCCESS;
				}
			}
		} while(zend_hash_move_forward_ex(ht, &hpos)==SUCCESS);
	}
	return FAILURE;
}
/* }}} */

static int oauth_provider_add_required_param(HashTable *ht, char *required_param) /* {{{ */
{
	zval zparam, *dest_entry;

	if((dest_entry = zend_hash_str_find(ht, required_param, strlen(required_param))) == NULL) {
		ZVAL_NULL(&zparam);
		if(zend_hash_str_add(ht, required_param, strlen(required_param), &zparam) == NULL) {
			return FAILURE;
		}
	}
	return SUCCESS;
}
/* }}} */

static void oauth_provider_apply_custom_param(HashTable *ht, HashTable *custom) /* {{{ */
{
	HashPosition custompos;
	zval *entry;
	zend_string *key;
	ulong num_key;

	zend_hash_internal_pointer_reset_ex(custom, &custompos);
	do {
		if ((entry = zend_hash_get_current_data_ex(custom, &custompos)) != NULL && HASH_KEY_IS_STRING == zend_hash_get_current_key_ex(custom, &key, &num_key, &custompos)) {
			if (IS_NULL == Z_TYPE_P(entry)) {
				zend_hash_del(ht, key);
			} else {
				Z_TRY_ADDREF_P(entry);
				zend_hash_update(ht, key, entry);
			}
		}
	} while (SUCCESS==zend_hash_move_forward_ex(custom, &custompos));
}
/* }}} */

static int oauth_provider_token_required(zval *provider_obj, char* uri)
{
	zval *is_req_token_api, rv;

	is_req_token_api = zend_read_property(Z_OBJCE_P(provider_obj), provider_obj, "request_token_endpoint", sizeof("request_token_endpoint") - 1, 1, &rv);

	if (Z_TYPE_P(is_req_token_api) == IS_FALSE) {
		php_oauth_provider *sop;

		sop = fetch_sop_object(provider_obj);
		/* do uri matching on the relative path */
		if (sop->endpoint_paths[OAUTH_PROVIDER_PATH_REQUEST]) {
			const char *reqtoken_path = sop->endpoint_paths[OAUTH_PROVIDER_PATH_REQUEST];
			int uri_matched = 0;

			if (reqtoken_path[0]=='/') {
				/* match against relative url */
				php_url *urlparts = php_url_parse_ex(uri, strlen(uri));
				uri_matched = urlparts && 0==strncmp(urlparts->path, reqtoken_path, strlen(reqtoken_path));
				php_url_free(urlparts);
			} else {
				/* match against full uri */
				uri_matched = 0==strncmp(uri, reqtoken_path, strlen(reqtoken_path));
			}

			/* token required if no match was found */
			if (uri_matched) {
				ZVAL_BOOL(is_req_token_api, 1);
				return 0;
			}
		}

		/* no matches, token required */
		return 1;
	}
	return 0;
}

static void oauth_provider_check_required_params(HashTable *required_params, HashTable *params, HashTable *missing_params) /* {{{ */
{
	HashPosition hpos, reqhpos, paramhpos;
	zval *dest_entry, param;
	zend_string *key;
	ulong num_key;

	zend_hash_internal_pointer_reset_ex(required_params, &hpos);
	zend_hash_internal_pointer_reset_ex(params, &reqhpos);
	zend_hash_internal_pointer_reset_ex(missing_params, &paramhpos);
	do {
		if(zend_hash_get_current_key_ex(required_params, &key, &num_key, &hpos) == HASH_KEY_IS_STRING) {
			if((dest_entry = zend_hash_find(params, key)) == NULL) {
				ZVAL_STRING(&param, ZSTR_VAL(key));
				zend_hash_next_index_insert(missing_params, &param);
			}
		}
	} while(zend_hash_move_forward_ex(required_params, &hpos)==SUCCESS);
}
/* }}} */

static void oauth_provider_set_std_params(zval *provider_obj, HashTable *sbs_vars) /* {{{ */
{
	zval *dest_entry;

	if(!provider_obj || !sbs_vars) {
		return;
	}

	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_CONSUMER_KEY, OAUTH_PROVIDER_CONSUMER_KEY);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_TOKEN, OAUTH_PROVIDER_TOKEN);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_SIGNATURE, OAUTH_PROVIDER_SIGNATURE);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_NONCE, OAUTH_PROVIDER_NONCE);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_TIMESTAMP, OAUTH_PROVIDER_TIMESTAMP);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_VERSION, OAUTH_PROVIDER_VERSION);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_SIGNATURE_METHOD, OAUTH_PROVIDER_SIGNATURE_METHOD);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_CALLBACK, OAUTH_PROVIDER_CALLBACK);
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, OAUTH_PARAM_VERIFIER, OAUTH_PROVIDER_VERIFIER);
}
/* }}} */

static inline int oauth_provider_set_param_value(HashTable *ht, char *key, zval *val) /* {{{ */
{
	Z_TRY_ADDREF_P(val);
	return zend_hash_str_update(ht, key, strlen(key), val) != NULL;
}
/* }}} */

static int oauth_provider_parse_auth_header(php_oauth_provider *sop, char *auth_header) /* {{{ */
{
	pcre_cache_entry *pce;
	zval subpats, return_value, *item_param, *current_param, *current_val;
	HashPosition hpos;
	zend_string *regex = zend_string_init(OAUTH_REGEX, sizeof(OAUTH_REGEX) - 1, 0);
	size_t decoded_len;

	if(!auth_header || strncasecmp(auth_header, "oauth", 4) || !sop) {
		return FAILURE;
	}
	/* pass "OAuth " */
	auth_header += 5;

	if ((pce = pcre_get_compiled_regex_cache(regex)) == NULL) {
		zend_string_release(regex);
		return FAILURE;
	}
	zend_string_release(regex);

	ZVAL_NULL(&subpats);
	ZVAL_NULL(&return_value);

	php_pcre_match_impl(
		pce,
		auth_header,
		strlen(auth_header),
		&return_value,
		&subpats,
		1, /* global */
		1, /* use flags */
		2, /* PREG_SET_ORDER */
		0
	);

	if (0 == Z_LVAL(return_value)) {
		return FAILURE;
	}

	zend_hash_internal_pointer_reset_ex(Z_ARRVAL(subpats), &hpos);
	/* walk the oauth param names */
	do {
		if ((item_param = zend_hash_get_current_data_ex(Z_ARRVAL(subpats), &hpos)) != NULL) {
			zval decoded_val;
			char *tmp;
			/*
			 * item = array(
			 * 	1 => param name
			 *	2 => quoted value
			 *	3 => unquoted value (defined if matched)
			 * )
			 */
			current_param = zend_hash_index_find(Z_ARRVAL_P(item_param), 1);

			if ((current_val =zend_hash_index_find(Z_ARRVAL_P(item_param), 3)) == NULL) {
				current_val = zend_hash_index_find(Z_ARRVAL_P(item_param), 2);
			}

			tmp = estrndup(Z_STRVAL_P(current_val), Z_STRLEN_P(current_val));
			decoded_len = php_url_decode(tmp, Z_STRLEN_P(current_val));
			ZVAL_STRINGL(&decoded_val, tmp, decoded_len);

			if (oauth_provider_set_param_value(sop->oauth_params, Z_STRVAL_P(current_param), &decoded_val)==FAILURE) {
				return FAILURE;
			}
			Z_DELREF(decoded_val);
		}
	} while (SUCCESS==zend_hash_move_forward_ex(Z_ARRVAL(subpats), &hpos));

	zval_ptr_dtor(&return_value);
	zval_ptr_dtor(&subpats);

	return SUCCESS;
}
/* }}} */

static void oauth_provider_register_cb(INTERNAL_FUNCTION_PARAMETERS, int type) /* {{{ */
{
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;
	php_oauth_provider *sop;
	php_oauth_provider_fcall *cb;
	php_oauth_provider_fcall **tgt_cb;

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "f", &fci, &fci_cache)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(getThis());

	cb = emalloc(sizeof(php_oauth_provider_fcall));
	cb->fcall_info = emalloc(sizeof(zend_fcall_info));
	memcpy(cb->fcall_info, &fci, sizeof(zend_fcall_info));
	cb->fcall_info_cache = fci_cache;

	Z_ADDREF(cb->fcall_info->function_name);

	switch(type) {
		case OAUTH_PROVIDER_CONSUMER_CB:
			tgt_cb = &sop->consumer_handler;
			break;
		case OAUTH_PROVIDER_TOKEN_CB:
			tgt_cb = &sop->token_handler;
			break;
		case OAUTH_PROVIDER_TSNONCE_CB:
			tgt_cb = &sop->tsnonce_handler;
			break;
		default:
			php_error_docref(NULL, E_ERROR, "Invalid callback type for OAuthProvider");
			return;
	}

	OAUTH_PROVIDER_FREE_CB((*tgt_cb));
	(*tgt_cb) = cb;
}
/* }}} */

static zval *oauth_provider_call_cb(INTERNAL_FUNCTION_PARAMETERS, int type) /* {{{ */
{
	php_oauth_provider *sop;
	php_oauth_provider_fcall *cb = NULL;
	zval args, *pthis;
	char *errstr = "";
	zend_string *callable = NULL;

	pthis = getThis();
	sop = fetch_sop_object(pthis);

	switch(type) {
		case OAUTH_PROVIDER_CONSUMER_CB:
			cb = sop->consumer_handler;
			errstr = "Consumer key/secret handler not specified, did you set a valid callback via OAuthProvider::consumerHandler()?";
			break;
		case OAUTH_PROVIDER_TOKEN_CB:
			cb = sop->token_handler;
			errstr = "Token handler not specified, did you set a valid callback via OAuthProvider::tokenHandler()?";
			break;
		case OAUTH_PROVIDER_TSNONCE_CB:
			cb = sop->tsnonce_handler;
			errstr = "Timestamp/nonce handler not specified, did you set a valid callback via OAuthProvider::timestampNonceHandler()?";
			break;
		default:
			php_error_docref(NULL, E_ERROR, "Invalid callback type for OAuthProvider");
			return NULL;
	}

	if(!cb) {
		php_error_docref(NULL, E_ERROR, "%s", errstr);
		return NULL;
	}

	array_init(&args);
	add_next_index_zval(&args, pthis);
	Z_ADDREF_P(pthis);
	Z_ADDREF(args);

	errstr = NULL;
	if (!zend_is_callable(&cb->fcall_info->function_name, 0, &callable)) {
		if (errstr) {
			php_error_docref(NULL, E_WARNING, "Invalid callback: %s, %s", Z_STRVAL(cb->fcall_info->function_name), errstr);
			efree(errstr);
		} else {
			php_error_docref(NULL, E_WARNING, "Invalid callback: %s.", Z_STRVAL(cb->fcall_info->function_name));
		}
	} else if (errstr) {
		php_error_docref(NULL, E_WARNING, "%s", errstr);
		efree(errstr);
	}

	if (zend_fcall_info_call(cb->fcall_info, &cb->fcall_info_cache, return_value, &args)!=SUCCESS) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed calling callback %s", Z_STRVAL(cb->fcall_info->function_name));
	}

	zval_ptr_dtor(&args);

	return return_value;
}
/* }}} */

static char *oauth_provider_get_http_verb() /* {{{ */
{
	zval *tmp;

	zend_is_auto_global_str("_SERVER", sizeof("_SERVER")-1);

	if(Z_TYPE(PG(http_globals)[TRACK_VARS_SERVER]) != IS_UNDEF) {
		if((tmp = zend_hash_str_find(HASH_OF(&PG(http_globals)[TRACK_VARS_SERVER]), "REQUEST_METHOD", sizeof("REQUEST_METHOD") - 1)) != NULL ||
		   (tmp = zend_hash_str_find(HASH_OF(&PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_METHOD", sizeof("HTTP_METHOD") - 1)) != NULL
		  ) {
			return Z_STRVAL_P(tmp);
		}
	}
	return NULL;
}
/* }}} */

static char *oauth_provider_get_current_uri()
{
	zval *host, *port, *uri, *proto, *https;

	zend_is_auto_global_str("_SERVER", sizeof("_SERVER")-1);

	host = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_HOST", sizeof("HTTP_HOST") - 1);
	port = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "SERVER_PORT", sizeof("SERVER_PORT") - 1);
	uri = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "REQUEST_URI", sizeof("REQUEST_URI") - 1);
	proto = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_X_FORWARDED_PROTO", sizeof("HTTP_X_FORWARDED_PROTO") - 1);
	https = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "HTTPS", sizeof("HTTPS") - 1);

	if (host && port && uri)
	{
		char *tmp,*hostname,*colon_in_hostname;

		spprintf(&hostname, 0, "%s", Z_STRVAL_P(host));
		colon_in_hostname=strrchr(hostname,':');
		if(colon_in_hostname && ((https && Z_LVAL_P(port)==443) || (!https && Z_LVAL_P(port)==80)))
		{
			*colon_in_hostname=0;
		}
		if(proto && Z_STRLEN_P(proto))
		{
			spprintf(&tmp, 0, "%s://%s%s", Z_STRVAL_P(proto), hostname, Z_STRVAL_P(uri));
		}
		else if(https && Z_STRLEN_P(https)>0 && strcasecmp(Z_STRVAL_P(https),"off")!=0)
		{
			spprintf(&tmp, 0, "https://%s%s", hostname, Z_STRVAL_P(uri));
		}
		else
		{
			spprintf(&tmp, 0, "http://%s%s", hostname, Z_STRVAL_P(uri));
		}
		efree(hostname);
		return tmp;
	}

	return NULL;
}

/* {{{ proto void OAuthProvider::__construct()
   Instantiate a new OAuthProvider object */
SOP_METHOD(__construct)
{
	php_oauth_provider *sop;
	zval *params = NULL, *pthis = NULL, apache_get_headers, retval, *tmpzval, *item_param;
	char *authorization_header = NULL;
	zend_string *key;
	ulong num_key = 0, param_count = 0;
	HashPosition hpos;

	pthis = getThis();

	sop = fetch_sop_object(pthis);

	/* XXX throw E_NOTICE if filter!='unsafe_raw' */
	if(zend_parse_parameters(ZEND_NUM_ARGS(), "|z", &params)==FAILURE) {
		soo_handle_error(NULL, OAUTH_ERR_INTERNAL_ERROR, "Failed to instantiate OAuthProvider", NULL, NULL);
		return;
	}

	if (params && Z_TYPE_P(params)==IS_ARRAY) {
		param_count = zend_hash_num_elements(Z_ARRVAL_P(params));
	} else {
		param_count = 0;
	}
	if(!strcasecmp("cli", sapi_module.name) && !param_count) {
		php_error_docref(NULL, E_ERROR, "For the CLI sapi parameters must be set first via OAuthProvider::__construct(array(\"oauth_param\" => \"value\", ...))");
		return;
	}

	/* hashes for storing parameter info/checks */
	ALLOC_HASHTABLE(sop->oauth_params);
	zend_hash_init(sop->oauth_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	ALLOC_HASHTABLE(sop->missing_params);
	zend_hash_init(sop->missing_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	ALLOC_HASHTABLE(sop->required_params);
	zend_hash_init(sop->required_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	ALLOC_HASHTABLE(sop->custom_params);
	zend_hash_init(sop->custom_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	memset(sop->endpoint_paths, 0, sizeof(sop->endpoint_paths));

	sop->consumer_handler = NULL;
	sop->token_handler = NULL;
	sop->tsnonce_handler = NULL;
	sop->handle_errors = 1;

	oauth_provider_set_default_required_params(sop->required_params);

	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_KEY, sizeof(OAUTH_PROVIDER_CONSUMER_KEY)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_SECRET, sizeof(OAUTH_PROVIDER_CONSUMER_SECRET)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_NONCE, sizeof(OAUTH_PROVIDER_NONCE)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TOKEN, sizeof(OAUTH_PROVIDER_TOKEN)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TOKEN_SECRET, sizeof(OAUTH_PROVIDER_TOKEN_SECRET)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TIMESTAMP, sizeof(OAUTH_PROVIDER_TIMESTAMP)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_VERSION, sizeof(OAUTH_PROVIDER_VERSION)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE_METHOD, sizeof(OAUTH_PROVIDER_SIGNATURE_METHOD)-1);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CALLBACK, sizeof(OAUTH_PROVIDER_CALLBACK)-1);

	zend_update_property_bool(Z_OBJCE_P(pthis), pthis, "request_token_endpoint", sizeof("request_token_endpoint")-1, 0);

	if(!param_count) {
		/* TODO: support NSAPI */
		/* mod_php */
		if(!strncasecmp(sapi_module.name, "apache", sizeof("apache") - 1)) {
			ZVAL_STRING(&apache_get_headers, "apache_request_headers");

			if(zend_is_callable(&apache_get_headers, 0, NULL)) {
				if(call_user_function(EG(function_table), NULL, &apache_get_headers, &retval, 0, NULL)) {
					php_error_docref(NULL, E_ERROR, "Failed to get HTTP Request headers");
				}
				if((tmpzval = zend_hash_str_find(HASH_OF(&retval), "Authorization", sizeof("Authorization") - 1)) != NULL) {
					authorization_header = estrdup(Z_STRVAL_P(tmpzval));
				} else if ((tmpzval = zend_hash_str_find(HASH_OF(&retval), "authorization", sizeof("authorization") - 1)) != NULL) {
					authorization_header = estrdup(Z_STRVAL_P(tmpzval));
				} else {
					/* search one by one */
					zend_hash_internal_pointer_reset_ex(HASH_OF(&retval), &hpos);
					do {
						if (FAILURE != zend_hash_get_current_key_ex(HASH_OF(&retval), &key, &num_key, &hpos) && ZSTR_LEN(key) == sizeof("authorization") && 0 == strcasecmp(ZSTR_VAL(key), "authorization") && (tmpzval = zend_hash_get_current_data_ex(HASH_OF(&retval), &hpos)) != NULL) {
							authorization_header = estrdup(Z_STRVAL_P(tmpzval));
							break;
						}
					} while (SUCCESS==zend_hash_move_forward_ex(HASH_OF(&retval), &hpos));
				}
			} else {
				php_error_docref(NULL, E_ERROR, "Failed to call apache_request_headers while running under the Apache SAPI");
			}
			zval_ptr_dtor(&apache_get_headers);
			zval_ptr_dtor(&retval);
		} else { /* not mod_php, look in _SERVER and _ENV for Authorization header */
			if(!zend_is_auto_global_str("_SERVER", sizeof("_SERVER") - 1) && !zend_is_auto_global_str("_ENV", sizeof("_ENV") - 1)) {
				return;
			}

			/* first look in _SERVER */
			if (Z_TYPE(PG(http_globals)[TRACK_VARS_SERVER]) == IS_UNDEF ||
					((tmpzval = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION") - 1)) == NULL
					 && (tmpzval = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "REDIRECT_HTTP_AUTHORIZATION", sizeof("REDIRECT_HTTP_AUTHORIZATION") -1)) == NULL))
			{
				/* well that didn't work out, so let's check out _ENV */
				if (Z_TYPE(PG(http_globals)[TRACK_VARS_ENV]) == IS_UNDEF
						|| (tmpzval = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_ENV]), "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION"))) == NULL)  {
					/* not found, [bf]ail */
					return;
				}
			}
			authorization_header = estrdup(Z_STRVAL_P(tmpzval));
		}
		if (authorization_header) {
			int ret = oauth_provider_parse_auth_header(sop, authorization_header);

			efree(authorization_header);

			if (FAILURE==ret) {
				soo_handle_error(NULL, OAUTH_SIGNATURE_METHOD_REJECTED, "Unknown signature method", NULL, NULL);
				return;
			}
		}
	}
	/* let constructor params override any values that may have been found in auth headers */
	if (param_count) {
		zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(params), &hpos);
		do {
			if(zend_hash_get_current_key_ex(Z_ARRVAL_P(params), &key, &num_key, &hpos) == HASH_KEY_IS_STRING) {
				if((item_param = zend_hash_get_current_data_ex(Z_ARRVAL_P(params), &hpos)) != NULL) {
					if(oauth_provider_set_param_value(sop->oauth_params, ZSTR_VAL(key), item_param) == FAILURE) {
						return;
					}
				}
			}
		} while(zend_hash_move_forward_ex(Z_ARRVAL_P(params), &hpos)==SUCCESS);
	}
}
/* }}} */

/* {{{ proto void OAuthProvider::callConsumerHandler()
   calls the registered consumer key handler function */
SOP_METHOD(callconsumerHandler)
{
	OAUTH_PROVIDER_CALL_CB(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_CONSUMER_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::callTokenHandler()
   calls the registered token handler function */
SOP_METHOD(calltokenHandler)
{
	OAUTH_PROVIDER_CALL_CB(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TOKEN_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::callTokenHandler()
   calls the registered token handler function */
SOP_METHOD(callTimestampNonceHandler)
{
	OAUTH_PROVIDER_CALL_CB(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TSNONCE_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::consumerHandler(callback cb) */
SOP_METHOD(consumerHandler)
{
	oauth_provider_register_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_CONSUMER_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::tokenHandler(callback cb) */
SOP_METHOD(tokenHandler)
{
	oauth_provider_register_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TOKEN_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::timestampNonceHandler(callback cb) */
SOP_METHOD(timestampNonceHandler)
{
	oauth_provider_register_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TSNONCE_CB);
}
/* }}} */

/* {{{ proto void OAuthProvider::isRequestTokenEndpoint(bool will_issue_request_token) */
SOP_METHOD(isRequestTokenEndpoint)
{
	zend_bool req_api = 0;
	zval *pthis;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Ob", &pthis, oauthprovider, &req_api)==FAILURE) {
		return;
	}

	zend_update_property_bool(Z_OBJCE_P(pthis), pthis, "request_token_endpoint", sizeof("request_token_endpoint") - 1, req_api);
}
/* }}} */

SOP_METHOD(setRequestTokenPath)
{
	zval *pthis;
	php_oauth_provider *sop;
	char *path;
	size_t path_len;

	if (FAILURE==zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Os", &pthis, oauthprovider, &path, &path_len)) {
		return;
	}

	sop = fetch_sop_object(pthis);

	OAUTH_PROVIDER_SET_ENDPOINT(sop->endpoint_paths[OAUTH_PROVIDER_PATH_REQUEST], path)

	RETURN_TRUE;
}

/* {{{ proto void OAuthProvider::checkOAuthRequest([string url [, string request_method]]) */
SOP_METHOD(checkOAuthRequest)
{
	zval *retval = NULL, *param, *pthis, *token_secret = NULL, *consumer_secret, *req_signature, *sig_method = NULL, rv;
	oauth_sig_context *sig_ctx = NULL;
	php_oauth_provider *sop;
	ulong missing_param_count = 0, mp_count = 1;
	char additional_info[512] = "", *http_verb = NULL, *uri = NULL, *current_uri = NULL;
	zend_string *sbs, *signature = NULL;
	HashPosition hpos;
	HashTable *sbs_vars = NULL;
	size_t http_verb_len = 0, uri_len = 0;
	int is_token_required = 0;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "O|ss", &pthis, oauthprovider, &uri, &uri_len, &http_verb, &http_verb_len)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(pthis);

	if(!http_verb_len) {
		http_verb = oauth_provider_get_http_verb();
	}


	if(!http_verb) {
		php_error_docref(NULL, E_ERROR, "Failed to detect HTTP method, set a HTTP method via OAuthProvider::checkOAuthRequest()");
		return;
	}

	ALLOC_HASHTABLE(sbs_vars);
	zend_hash_init(sbs_vars, 0, NULL, ZVAL_PTR_DTOR, 0);

	if(Z_TYPE(PG(http_globals)[TRACK_VARS_GET]) != IS_UNDEF) {
		zend_hash_merge(sbs_vars, HASH_OF(&PG(http_globals)[TRACK_VARS_GET]), (copy_ctor_func_t)zval_add_ref, 0);
	}
	if(Z_TYPE(PG(http_globals)[TRACK_VARS_POST]) != IS_UNDEF) {
		zend_hash_merge(sbs_vars, HASH_OF(&PG(http_globals)[TRACK_VARS_POST]), (copy_ctor_func_t)zval_add_ref, 0);
	}
	if(zend_hash_num_elements(sop->oauth_params)) {
		zend_hash_merge(sbs_vars, sop->oauth_params, (copy_ctor_func_t)zval_add_ref, 0);
	}

	if (zend_hash_num_elements(sop->custom_params)) {
		/* apply custom params */
		oauth_provider_apply_custom_param(sbs_vars, sop->custom_params);
	}

	zend_hash_internal_pointer_reset_ex(sbs_vars, &hpos);

	/* set the standard stuff present in every request if its found in sbs_vars, IE if we find oauth_consumer_key, set $oauth->consumer_key */
	oauth_provider_set_std_params(pthis, sbs_vars);

	if (!uri) {
		/* get current uri */
		uri = current_uri = oauth_provider_get_current_uri();
	}

	/* if we are in an API which issues a request token, there are is no token handler called */
	if (!(is_token_required=oauth_provider_token_required(pthis, uri))) {
		/* by default, oauth_token is required; remove from the required list */
		oauth_provider_remove_required_param(sop->required_params, "oauth_token");
	}

	oauth_provider_check_required_params(sop->required_params, sbs_vars, sop->missing_params);

	missing_param_count = zend_hash_num_elements(sop->missing_params);
	if(missing_param_count) {
		zend_hash_internal_pointer_reset_ex(sop->missing_params, &hpos);
		do {
			if((param = zend_hash_get_current_data_ex(sop->missing_params, &hpos)) != NULL) {
				snprintf(additional_info, 512, "%s%s%s", additional_info, Z_STRVAL_P(param), (missing_param_count > 1 && missing_param_count!=mp_count++) ? "%26" : "");
			}
		} while(zend_hash_move_forward_ex(sop->missing_params, &hpos)==SUCCESS);
		soo_handle_error(NULL, OAUTH_PARAMETER_ABSENT, "Missing required parameters", NULL, additional_info);
		FREE_ARGS_HASH(sbs_vars);
		OAUTH_PROVIDER_FREE_STRING(current_uri);
		return;
	}

	sig_method = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE_METHOD, sizeof(OAUTH_PROVIDER_SIGNATURE_METHOD) - 1, 1, &rv);
	do {
		if (sig_method && (Z_TYPE_P(sig_method) == IS_STRING) && Z_STRLEN_P(sig_method)) {
			sig_ctx = oauth_create_sig_context(Z_STRVAL_P(sig_method));
			if (OAUTH_SIGCTX_TYPE_NONE!=sig_ctx->type) {
				break;
			}
			OAUTH_SIGCTX_FREE(sig_ctx);
		}
		soo_handle_error(NULL, OAUTH_SIGNATURE_METHOD_REJECTED, "Unknown signature method", NULL, NULL);
		FREE_ARGS_HASH(sbs_vars);
		OAUTH_PROVIDER_FREE_STRING(current_uri);
		return;
	} while (0);

	do {
		long cb_res;

		retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_CONSUMER_CB);
		if (retval) {
			convert_to_long(retval);
			cb_res = Z_LVAL_P(retval);
			zval_ptr_dtor(retval);

			if (OAUTH_OK!=cb_res) {
				soo_handle_error(NULL, cb_res, "Invalid consumer key", NULL, additional_info);
				break;
			}
		} else if (EG(exception)) {
			/* pass exceptions */
			break;
		}

		if (is_token_required) {
			retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TOKEN_CB);
			if (retval) {
				convert_to_long(retval);
				cb_res = Z_LVAL_P(retval);
				zval_ptr_dtor(retval);

				if (OAUTH_OK!=cb_res) {
					soo_handle_error(NULL, cb_res, "Invalid token", NULL, additional_info);
					break;
				}
			} else if (EG(exception)) {
				/* pass exceptions */
				break;
			}
		}

		retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TSNONCE_CB);
		if (retval) {
			convert_to_long(retval);
			cb_res = Z_LVAL_P(retval);
			zval_ptr_dtor(retval);

			if (OAUTH_OK!=cb_res) {
				soo_handle_error(NULL, cb_res, "Invalid nonce/timestamp combination", NULL, additional_info);
				break;
			}
		} else if (EG(exception)) {
			/* pass exceptions */
			break;
		}

		/* now for the signature stuff */
		sbs = oauth_generate_sig_base(NULL, http_verb, uri, sbs_vars, NULL);

		if (sbs) {
			consumer_secret = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_SECRET, sizeof(OAUTH_PROVIDER_CONSUMER_SECRET) - 1, 1, &rv);
			convert_to_string_ex(consumer_secret);
			if (is_token_required) {
				token_secret = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TOKEN_SECRET, sizeof(OAUTH_PROVIDER_TOKEN_SECRET) - 1, 1, &rv);
				convert_to_string_ex(token_secret);
			}
			signature = soo_sign(NULL, ZSTR_VAL(sbs), consumer_secret, token_secret, sig_ctx);
		}

		req_signature = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE, sizeof(OAUTH_PROVIDER_SIGNATURE) - 1, 1, &rv);
		if (!signature || !Z_STRLEN_P(req_signature) || strcmp(ZSTR_VAL(signature), Z_STRVAL_P(req_signature))) {
			soo_handle_error(NULL, OAUTH_INVALID_SIGNATURE, "Signatures do not match", NULL, sbs ? ZSTR_VAL(sbs) : NULL);
		}

		if (sbs) {
			zend_string_release(sbs);
		}
		if (signature) {
			zend_string_release(signature);
		}
	} while (0);

	OAUTH_SIGCTX_FREE(sig_ctx);
	OAUTH_PROVIDER_FREE_STRING(current_uri);
	FREE_ARGS_HASH(sbs_vars);
}
/* }}} */

/* {{{ proto void OAuthProvider::addRequiredParameter(string $required_param) */
SOP_METHOD(addRequiredParameter)
{
	zval *pthis;
	char *required_param;
	php_oauth_provider *sop;
	size_t req_param_len;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Os", &pthis, oauthprovider, &required_param, &req_param_len)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(pthis);

	if(oauth_provider_add_required_param(sop->required_params, required_param)==SUCCESS) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto void OAuthProvider::setParam(string $key, mixed $val) */
SOP_METHOD(setParam)
{
	zval *pthis, *param_val = NULL;
	char *param_key;
	size_t param_key_len;
	php_oauth_provider *sop;

	if (FAILURE==zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Os|z/", &pthis, oauthprovider, &param_key, &param_key_len, &param_val)) {
		return;
	}

	sop = fetch_sop_object(pthis);

	if (!param_val) {
		RETURN_BOOL(SUCCESS == zend_hash_str_del(sop->custom_params, param_key, param_key_len) ? IS_TRUE : IS_FALSE);
	} else {
		Z_TRY_ADDREF_P(param_val);

		RETURN_BOOL(NULL != zend_hash_str_add(sop->custom_params, param_key, param_key_len, param_val) ? IS_TRUE : IS_FALSE);
	}
}
/* }}} */

/* {{{ proto void OAuthProvider::removeRequiredParameter(string $required_param) */
SOP_METHOD(removeRequiredParameter)
{
	zval *pthis;
	char *required_param;
	php_oauth_provider *sop;
	size_t req_param_len;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS(), getThis(), "Os", &pthis, oauthprovider, &required_param, &req_param_len)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(pthis);

	if(oauth_provider_remove_required_param(sop->required_params, required_param)==SUCCESS) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto string OAuthProvider::generateToken(int $size[, bool $string = false]) */
SOP_METHOD(generateToken)
{
	long size, reaped = 0;
	int strong = 0;
	char *iv = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|b", &size, &strong)==FAILURE) {
		return;
	}

	if (size < 1 || size > INT_MAX) {
		php_error_docref(NULL, E_WARNING, "Cannot generate token with a size of less than 1 or greater than %d", INT_MAX);
		return;
	}

	iv = ecalloc(size+1, 1);

	do {
#if PHP_WIN32
/*
 * The Windows port has been ripped from the mcrypt extension; thanks guys! ;-)
 */
		HCRYPTPROV hCryptProv;
		BYTE *iv_b = (BYTE *) iv;

		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			break;
		}
		if (!CryptGenRandom(hCryptProv, size, iv_b)) {
			break;
		}
		reaped = size;
#else
		int fd;

		fd = open(strong?"/dev/random":"/dev/urandom", O_RDONLY);
		if (fd < 0) {
			break;
		}
		while (reaped < size) {
			register int n;
			n = read(fd, iv + reaped, size - reaped);
			if (n < 0) {
				break;
			}
			reaped += n;
		}
		close(fd);
#endif
	} while (0);

	if (reaped < size) {
		if (strong) {
			php_error_docref(NULL, E_WARNING, "Could not gather enough random data, falling back on rand()");
		}
		while (reaped < size) {
			iv[reaped++] = (char) (255.0 * php_rand() / RAND_MAX);
		}
	}

	RETURN_STRINGL(iv, size);
}
/* }}} */

/* {{{ proto void OAuthProvider::reportProblem(Exception $e) */
SOP_METHOD(reportProblem)
{
	zval *exception, *code, *sbs, *missing_params, rv;
	zend_class_entry *ex_ce;
	zend_bool out_malloced = 0;
	char *out, *tmp_out, *http_header_line;
	size_t pr_len;
	ulong lcode;
	uint http_code;
	sapi_header_line ctr = {0};
	zend_bool send_headers = 1;

	ex_ce = zend_exception_get_default();

	if(zend_parse_parameters(ZEND_NUM_ARGS(), "O|b", &exception, ex_ce, &send_headers)==FAILURE) {
		return;
	}

	/* XXX good candidate for refactoring */
	code = zend_read_property(Z_OBJCE_P(exception), exception, "code", sizeof("code") - 1, 1, &rv);
	lcode = Z_LVAL_P(code);

	switch(lcode) {
		case OAUTH_BAD_TIMESTAMP:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=timestamp_refused"; break;
		case OAUTH_BAD_NONCE:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=nonce_used"; break;
		case OAUTH_CONSUMER_KEY_UNKNOWN:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=consumer_key_unknown"; break;
		case OAUTH_CONSUMER_KEY_REFUSED:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=consumer_key_refused"; break;
		case OAUTH_TOKEN_USED:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=token_used"; break;
		case OAUTH_TOKEN_EXPIRED:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=token_expired"; break;
		case OAUTH_TOKEN_REVOKED:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=token_revoked"; break;
		case OAUTH_TOKEN_REJECTED:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=token_rejected"; break;
		case OAUTH_VERIFIER_INVALID:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=verifier_invalid"; break;
		case OAUTH_INVALID_SIGNATURE:
			http_code = OAUTH_ERR_BAD_AUTH;
			out = "oauth_problem=signature_invalid";
			sbs = zend_read_property(Z_OBJCE_P(exception), exception, "additionalInfo", sizeof("additionalInfo") - 1, 1, &rv);
			if (sbs && IS_NULL!=Z_TYPE_P(sbs)) {
				convert_to_string_ex(sbs);
				if(Z_STRLEN_P(sbs)) {
					pr_len = Z_STRLEN_P(sbs) + strlen(out) + sizeof("&debug_sbs=");
					tmp_out = emalloc(pr_len);
					/* sbs url encoded so XSS shouldn't be an issue here */
					snprintf(tmp_out, pr_len, "%s&debug_sbs=%s", out, Z_STRVAL_P(sbs));
					out = tmp_out;
					out_malloced = 1;
				}
			}
			break;
		case OAUTH_SIGNATURE_METHOD_REJECTED:
			http_code = OAUTH_ERR_BAD_REQUEST;
			out = "oauth_problem=signature_method_rejected"; break;
		case OAUTH_PARAMETER_ABSENT:
			http_code = OAUTH_ERR_BAD_REQUEST;
			out = "oauth_problem=parameter_absent";
			missing_params = zend_read_property(Z_OBJCE_P(exception), exception, "additionalInfo", sizeof("additionalInfo") - 1, 1, &rv);
			if(missing_params) {
				convert_to_string_ex(missing_params);
				if(Z_STRLEN_P(missing_params)) {
					pr_len = Z_STRLEN_P(missing_params) + strlen(out) + sizeof("&oauth_parameters_absent=");
					tmp_out = emalloc(pr_len);
					snprintf(tmp_out, pr_len, "%s&oauth_parameters_absent=%s", out, Z_STRVAL_P(missing_params));
					out = tmp_out;
					out_malloced = 1;
				}
			}
			break;
		default:
			http_code = OAUTH_ERR_INTERNAL_ERROR;
			out = emalloc(48);
			snprintf(out, 48, "oauth_problem=unknown_problem&code=%d", lcode);
			out_malloced = 1;
	}

	ZVAL_STRINGL(return_value, out, strlen(out));

	if(send_headers) {
		if(http_code==OAUTH_ERR_BAD_REQUEST) {
			http_header_line = "HTTP/1.1 400 Bad Request";
		} else {
			http_header_line = "HTTP/1.1 401 Unauthorized";
		}

		ctr.line = http_header_line;
		ctr.line_len = strlen(http_header_line);
		ctr.response_code = http_code;

		sapi_header_op(SAPI_HEADER_REPLACE, &ctr);
	}

	if(out_malloced) {
		efree(out);
	}
}
/* }}} */

static void oauth_provider_free_storage(zend_object *obj) /* {{{ */
{
	php_oauth_provider *sop;

	sop = sop_object_from_obj(obj);

	zend_object_std_dtor(&sop->zo);

	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->consumer_handler);
	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->token_handler);
	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->tsnonce_handler);
	FREE_ARGS_HASH(sop->missing_params);
	FREE_ARGS_HASH(sop->oauth_params);
	FREE_ARGS_HASH(sop->required_params);
	FREE_ARGS_HASH(sop->custom_params);

	OAUTH_PROVIDER_FREE_STRING(sop->endpoint_paths[OAUTH_PROVIDER_PATH_REQUEST]);
	OAUTH_PROVIDER_FREE_STRING(sop->endpoint_paths[OAUTH_PROVIDER_PATH_ACCESS]);
	OAUTH_PROVIDER_FREE_STRING(sop->endpoint_paths[OAUTH_PROVIDER_PATH_AUTH]);
}
/* }}} */

static zend_object* oauth_provider_new(zend_class_entry *ce) /* {{{ */
{
	php_oauth_provider *nos;
	nos = ecalloc(1, sizeof(php_oauth_provider) + zend_object_properties_size(ce));

	zend_object_std_init(&nos->zo, ce);
	object_properties_init(&nos->zo, ce);

	nos->zo.handlers = &oauth_provider_obj_hndlrs;

	return &nos->zo;
}
/* }}} */

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider__construct, 0, 0, 0)
ZEND_ARG_INFO(0, params_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_check, 0, 0, 0)
ZEND_ARG_INFO(0, uri)
ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_handler, 0, 0, 1)
ZEND_ARG_INFO(0, function_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_reportproblem, 0, 0, 1)
ZEND_ARG_INFO(0, oauthexception)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_req_token, 0, 0, 1)
ZEND_ARG_INFO(0, params_array)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_set_req_param, 0, 0, 1)
ZEND_ARG_INFO(0, req_params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_set_param, 0, 0, 1)
ZEND_ARG_INFO(0, param_key)
ZEND_ARG_INFO(0, param_val)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_set_path, 0, 0, 1)
ZEND_ARG_INFO(0, path)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_generate_token, 0, 0, 1)
ZEND_ARG_INFO(0, size)
ZEND_ARG_INFO(0, strong)
ZEND_END_ARG_INFO()

static zend_function_entry oauth_provider_methods[] = { /* {{{ */
		SOP_ME(__construct,			arginfo_oauth_provider__construct,		ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
		SOP_ME(consumerHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(tokenHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(timestampNonceHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(callconsumerHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(calltokenHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(callTimestampNonceHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(checkOAuthRequest,	arginfo_oauth_provider_check,		ZEND_ACC_PUBLIC)
		SOP_ME(isRequestTokenEndpoint,	arginfo_oauth_provider_req_token,		ZEND_ACC_PUBLIC)
		SOP_ME(setRequestTokenPath,	arginfo_oauth_provider_set_path,	ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		SOP_ME(addRequiredParameter,	arginfo_oauth_provider_set_req_param,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		SOP_ME(reportProblem,	arginfo_oauth_provider_reportproblem,		ZEND_ACC_PUBLIC|ZEND_ACC_STATIC|ZEND_ACC_FINAL)
		SOP_ME(setParam, 		arginfo_oauth_provider_set_param,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		SOP_ME(removeRequiredParameter,	arginfo_oauth_provider_set_req_param,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		SOP_ME(generateToken,		arginfo_oauth_provider_generate_token,		ZEND_ACC_PUBLIC|ZEND_ACC_STATIC|ZEND_ACC_FINAL)
		PHP_MALIAS(oauthprovider,	is2LeggedEndpoint, isRequestTokenEndpoint, arginfo_oauth_provider_req_token, ZEND_ACC_PUBLIC)
		{NULL, NULL, NULL}
};

extern int oauth_provider_register_class() /* {{{ */
{
	zend_class_entry osce;

	INIT_CLASS_ENTRY(osce, "OAuthProvider", oauth_provider_methods);
	osce.create_object = oauth_provider_new;
	oauthprovider = zend_register_internal_class(&osce);

	memcpy(&oauth_provider_obj_hndlrs, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	oauth_provider_obj_hndlrs.offset = XtOffsetOf(php_oauth_provider, zo);
	oauth_provider_obj_hndlrs.free_obj = oauth_provider_free_storage;

	return SUCCESS;
}
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

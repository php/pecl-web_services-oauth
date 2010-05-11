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

static zend_object_handlers oauth_provider_obj_hndlrs;
static zend_class_entry *oauthprovider;

static inline void oauth_provider_set_param_member(zval *provider_obj, char *prop_name, zval *prop TSRMLS_DC) /* {{{ */
{
	zend_update_property(Z_OBJCE_P(provider_obj), provider_obj, prop_name, strlen(prop_name), prop TSRMLS_CC);
}
/* }}} */

static inline php_oauth_provider *fetch_sop_object(zval *obj TSRMLS_DC) /* {{{ */
{
	php_oauth_provider *sop = (php_oauth_provider *)zend_object_store_get_object(obj TSRMLS_CC);
	sop->this_ptr = obj;
	return sop;
}
/* }}} */

static int oauth_provider_set_default_required_params(HashTable *ht) /* {{{ */
{
	char *required_params[] = {"oauth_consumer_key", "oauth_signature", "oauth_signature_method", "oauth_nonce", "oauth_timestamp", "oauth_token", NULL};
	unsigned int idx = 0;

	do {
		zval *tmp;
		MAKE_STD_ZVAL(tmp);
		ZVAL_NULL(tmp);
		if(zend_hash_add(ht, required_params[idx], strlen(required_params[idx]) + 1, &tmp, sizeof(zval *), NULL)==FAILURE) {
			return FAILURE;
		}
		++idx;
	} while(required_params[idx]);

	return SUCCESS;
}
/* }}} */

static int oauth_provider_remove_required_param(HashTable *ht, char *required_param) /* {{{ */
{
	zval **dest_entry;
	char *key;
	uint key_len;
	ulong num_key;
	HashPosition hpos;

	if(zend_hash_find(ht, required_param, strlen(required_param) + 1, (void **)&dest_entry)==FAILURE) {
		return FAILURE;
	} else {
		zend_hash_internal_pointer_reset_ex(ht, &hpos);
		do {
			if(zend_hash_get_current_key_ex(ht, &key, &key_len, &num_key, 0, &hpos)!=FAILURE) {
				if(!strcmp(key, required_param)) {
					zend_hash_del(ht, key, key_len);
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
	zval *zparam, **dest_entry;

	if(zend_hash_find(ht, required_param, strlen(required_param) + 1, (void **)&dest_entry)==FAILURE) {
		MAKE_STD_ZVAL(zparam);
		ZVAL_NULL(zparam);
		if(zend_hash_add(ht, required_param, strlen(required_param) + 1, &zparam, sizeof(zval *), NULL)==FAILURE) {
			return FAILURE;
		}
	}
	return SUCCESS;
}
/* }}} */

static void oauth_provider_check_required_params(HashTable *required_params, HashTable *params, HashTable *missing_params TSRMLS_DC) /* {{{ */
{
	HashPosition hpos, reqhpos, paramhpos;
	zval **dest_entry, *param;
	char *key;
	ulong num_key;
	uint key_len;

	zend_hash_internal_pointer_reset_ex(required_params, &hpos);
	zend_hash_internal_pointer_reset_ex(params, &reqhpos);
	zend_hash_internal_pointer_reset_ex(missing_params, &paramhpos);
	do {
		if(zend_hash_get_current_key_ex(required_params, &key, &key_len, &num_key, 0, &hpos)==HASH_KEY_IS_STRING) {
			if(zend_hash_find(params, key, key_len, (void **)&dest_entry)==FAILURE) {
				MAKE_STD_ZVAL(param);
				ZVAL_STRING(param, key, 1);
				zend_hash_next_index_insert(missing_params, &param, sizeof(zval *), NULL);
			}
		}
	} while(zend_hash_move_forward_ex(required_params, &hpos)==SUCCESS);
}
/* }}} */


static void oauth_provider_set_std_params(zval *provider_obj, HashTable *sbs_vars TSRMLS_DC) /* {{{ */
{
	zval **dest_entry;

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
	OAUTH_PROVIDER_SET_STD_PARAM(sbs_vars, "oauth_callback", "callback");
}
/* }}} */

static inline int oauth_provider_set_param_value(HashTable *ht, char *key, zval **val) /* {{{ */
{
	ulong h;
	ulong key_len = 0;

	key_len = strlen(key);
	h = zend_hash_func(key, key_len+1);
	Z_ADDREF_P(*val);
	return zend_hash_quick_update(ht, key, key_len+1, h, val, sizeof(zval **), NULL);
}
/* }}} */

static int *oauth_provider_parse_auth_header(php_oauth_provider *sop, char *auth_header TSRMLS_DC) /* {{{ */
{
	pcre_cache_entry *pce;
	zval *subpats = NULL, *return_value = NULL, **oauth_params = NULL, **item_param = NULL, **item_val = NULL, **current_param = NULL, **oauth_vals = NULL, **current_val = NULL;
	HashPosition hpos;
	ulong num_key = 0;
	/* the following regex is also used at http://oauth.googlecode.com/svn/code/php/OAuth.php to help ensure uniform behavior between libs, credit goes to the original author(s) */
	char *key = NULL, *regex = "/((oauth_([-_a-z]*))=(\"([^\"]*)\"|([^,]*)),?)/";

	if(!auth_header || strncasecmp(auth_header, "oauth", 4) || !sop) {
		return NULL;
	}
	/* pass "OAuth " */
	auth_header += 5;

	if ((pce = pcre_get_compiled_regex_cache(regex, sizeof(regex)-1 TSRMLS_CC)) == NULL) {
		return NULL;
	}

	ALLOC_ZVAL(return_value);
	MAKE_STD_ZVAL(return_value);

	ALLOC_ZVAL(subpats);
	MAKE_STD_ZVAL(subpats);
	array_init(subpats);

	php_pcre_match_impl(pce, auth_header, strlen(auth_header), return_value, subpats, 1, 1, (1<<8), 0 TSRMLS_CC);

	/* oauth param value subpat */
	if(zend_hash_index_find(Z_ARRVAL_P(subpats), 5, (void **)&oauth_vals)==FAILURE) {
		return NULL;
	}

	if(zend_hash_index_find(Z_ARRVAL_P(subpats), 2, (void **)&oauth_params)==SUCCESS) {
		zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(oauth_params), &hpos);
		/* walk the oauth param names */
		do {
			if(zend_hash_get_current_key_ex(Z_ARRVAL_PP(oauth_params), &key, NULL, &num_key, 0, &hpos)==HASH_KEY_IS_LONG) {
				if(zend_hash_get_current_data_ex(Z_ARRVAL_PP(oauth_params), (void **)&item_param, &hpos)!=FAILURE) {
					/* get the actual param name subpat (item = Array
					 * (
					 *     [0] => oauth_consumer_key
					 *	   ...
					 * )
					 */
					zend_hash_index_find(Z_ARRVAL_PP(item_param), 0, (void **)&current_param);

					/* get the parameter's value subpat (val = Array
					 *  (
					 *     [0] => 0685bd9184jfhq22
					 *     ...
					 *  )
					 * */
					zend_hash_index_find(Z_ARRVAL_PP(oauth_vals), num_key, (void **)&item_val);
					zend_hash_index_find(Z_ARRVAL_PP(item_val), 0, (void **)&current_val);
					if(oauth_provider_set_param_value(sop->oauth_params, Z_STRVAL_PP(current_param), current_val)==FAILURE) {
						return NULL;
					}
				}
			}
		} while(zend_hash_move_forward_ex(Z_ARRVAL_PP(oauth_params), &hpos)==SUCCESS);
	}
	/*while(*auth_header) {
	  if(*auth_header!=' ' && *auth_header!='\n' && *auth_header!='\t' && *auth_header!='\r') {
	  fprintf(stdout, "auth header: %s\n", auth_header);
	  }
	  auth_header++;
	  }*/
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

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "f", &fci, &fci_cache)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(getThis() TSRMLS_CC);

	cb = emalloc(sizeof(php_oauth_provider_fcall));
	cb->fcall_info = emalloc(sizeof(zend_fcall_info));
	memcpy(cb->fcall_info, &fci, sizeof(zend_fcall_info));
	cb->fcall_info_cache = fci_cache;

	Z_ADDREF_P(cb->fcall_info->function_name);

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
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid callback type for OAuthProvider");
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
	zval *retval, *args, *pthis;
	char *errstr = "";

	pthis = getThis();
	sop = fetch_sop_object(pthis TSRMLS_CC);

	switch(type) {
		case OAUTH_PROVIDER_CONSUMER_CB:
			cb = sop->consumer_handler;
			errstr = "Consumer key/secret handler not specified, did you set a valid callback via OAuthProvider::consumerKeyHandler()?";
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
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "Invalid callback type for OAuthProvider");
			return NULL;
	}

	if(!cb) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "%s", errstr);
		return NULL;
	}

	MAKE_STD_ZVAL(args);
	array_init(args);
	add_next_index_zval(args, pthis);
	Z_ADDREF_P(pthis);

	if(zend_fcall_info_call(cb->fcall_info, &cb->fcall_info_cache, &retval, args TSRMLS_CC)!=SUCCESS) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed calling callback %s", Z_STRVAL_P(cb->fcall_info->function_name));
	}
	zval_ptr_dtor(&args);

	return retval;
}
/* }}} */

static char *oauth_provider_get_http_verb(TSRMLS_D) /* {{{ */
{
	zval **tmp;
#ifndef TRACK_VARS_SERVER
	return NULL;
#else
	if(PG(http_globals)[TRACK_VARS_SERVER]) {
		if(zend_hash_find(HASH_OF(PG(http_globals)[TRACK_VARS_SERVER]), "REQUEST_METHOD", sizeof("REQUEST_METHOD"), (void **) &tmp)!=FAILURE || zend_hash_find(HASH_OF(PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_METHOD", sizeof("HTTP_METHOD"), (void **) &tmp)!=FAILURE) {
			return Z_STRVAL_PP(tmp);
		}
	}
	return NULL;
#endif
}
/* }}} */

/* {{{ proto void OAuthProvider::__construct()
   Instantiate a new OAuthProvider object */
SOP_METHOD(__construct)
{
	php_oauth_provider *sop;
	zval *params = NULL, *pthis = NULL, *auth_header = NULL, *apache_get_headers = NULL, *retval = NULL, **tmpzval = NULL, **item_param = NULL;
	char *authorization_header = NULL, *key = NULL;
	ulong num_key = 0, param_count = 0;
	HashPosition hpos;

	pthis = getThis();

	sop = fetch_sop_object(pthis TSRMLS_CC);

	/* XXX throw E_NOTICE if filter!='unsafe_raw' */
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|z", &params)==FAILURE) {
		return;
	}

	if (params && Z_TYPE_P(params)==IS_ARRAY) {
		param_count = zend_hash_num_elements(Z_ARRVAL_P(params));
	} else {
		param_count = 0;
	}
	if(!strcasecmp("cli", sapi_module.name) && !param_count) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "For the CLI sapi parameters must be set first via OAuthProvider::__construct(array(\"oauth_param\" => \"value\", ...))");
		return;
	} 

	/* hashes for storing parameter info/checks */
	ALLOC_HASHTABLE(sop->oauth_params);
	zend_hash_init(sop->oauth_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	ALLOC_HASHTABLE(sop->missing_params);
	zend_hash_init(sop->missing_params, 0, NULL, ZVAL_PTR_DTOR, 0);
	ALLOC_HASHTABLE(sop->required_params);
	zend_hash_init(sop->required_params, 0, NULL, ZVAL_PTR_DTOR, 0);

	sop->consumer_handler = NULL;
	sop->token_handler = NULL;
	sop->tsnonce_handler = NULL;
	sop->handle_errors = 1;

	oauth_provider_set_default_required_params(sop->required_params);

	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_KEY, sizeof(OAUTH_PROVIDER_CONSUMER_KEY)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_SECRET, sizeof(OAUTH_PROVIDER_CONSUMER_SECRET)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_NONCE, sizeof(OAUTH_PROVIDER_NONCE)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TOKEN, sizeof(OAUTH_PROVIDER_TOKEN)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TIMESTAMP, sizeof(OAUTH_PROVIDER_TIMESTAMP)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_VERSION, sizeof(OAUTH_PROVIDER_VERSION)-1 TSRMLS_CC);
	zend_update_property_null(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE_METHOD, sizeof(OAUTH_PROVIDER_SIGNATURE_METHOD)-1 TSRMLS_CC);

	zend_update_property_null(Z_OBJCE_P(pthis), pthis, "callback", sizeof("callback")-1 TSRMLS_CC);
	zend_update_property_bool(Z_OBJCE_P(pthis), pthis, "request_token_endpoint", sizeof("request_token_endpoint")-1, 0 TSRMLS_CC);

	if(!param_count) {
		/* TODO: support NSAPI */
		/* mod_php */
		if(!strncasecmp(sapi_module.name, "apache", sizeof("apache") - 1)) {
			MAKE_STD_ZVAL(apache_get_headers);
			MAKE_STD_ZVAL(retval);
			ZVAL_STRING(apache_get_headers, "apache_request_headers", 0);

			if(zend_is_callable(apache_get_headers, 0, NULL OAUTH_IS_CALLABLE_CC)) {
				if(call_user_function(EG(function_table), NULL, apache_get_headers, retval, 0, NULL TSRMLS_CC)) {
					php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to get HTTP Request headers");
				}
				if(SUCCESS == zend_hash_find(HASH_OF(retval), "Authorization", sizeof("Authorization"), (void **) &tmpzval)) {
					auth_header = *tmpzval;
					authorization_header = estrdup(Z_STRVAL_P(auth_header));
				}
			} else {
				php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to call apache_request_headers while running under the Apache SAPI");
			}
			FREE_ZVAL(apache_get_headers);
			zval_ptr_dtor(&retval);
		} else { /* not mod_php, look in _SERVER and _ENV for Authorization header */
			if(!zend_is_auto_global("_SERVER", sizeof("_SERVER") - 1 TSRMLS_CC) && !zend_is_auto_global("_ENV", sizeof("_ENV") - 1 TSRMLS_CC)) {
				return;
			}

			/* first look in _SERVER */
			if (!PG(http_globals)[TRACK_VARS_SERVER]
					|| zend_hash_find(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_SERVER]), "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION"), (void **) &tmpzval)==FAILURE) {
				/* well that didn't work out, so let's check out _ENV */
				if (!PG(http_globals)[TRACK_VARS_ENV]
						|| zend_hash_find(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_ENV]), "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION"), (void **) &tmpzval)==FAILURE) {
					/* not found, [bf]ail */
					return;
				}
			}
			auth_header = *tmpzval;
			authorization_header = estrdup(Z_STRVAL_P(auth_header));
		}
		if(!authorization_header || oauth_provider_parse_auth_header(sop, authorization_header TSRMLS_CC)!=SUCCESS) {
			efree(authorization_header);
			soo_handle_error(NULL, OAUTH_SIGNATURE_METHOD_REJECTED, "Unknown signature method", NULL, NULL TSRMLS_CC);
			return;
		}
		efree(authorization_header);
	}
	/* let constructor params override any values that may have been found in auth headers */
	if(param_count) {
		zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(params), &hpos);
		do {
			if(zend_hash_get_current_key_ex(Z_ARRVAL_P(params), &key, NULL, &num_key, 0, &hpos)==HASH_KEY_IS_STRING) {
				if(zend_hash_get_current_data_ex(Z_ARRVAL_P(params), (void **)&item_param, &hpos)!=FAILURE) {
					if(oauth_provider_set_param_value(sop->oauth_params, key, item_param)==FAILURE) {
						return;
					}
				}
			}
		} while(zend_hash_move_forward_ex(Z_ARRVAL_P(params), &hpos)==SUCCESS); 
	}
}
/* }}} */

/* {{{ proto void OAuthProvider::callConsumerKeyHandler()
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

/* {{{ proto void OAuthProvider::consumerKeyHandler(callback cb) */
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
	php_oauth_provider *sop;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Ob", &pthis, oauthprovider, &req_api)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(pthis TSRMLS_CC);

	zend_update_property_bool(Z_OBJCE_P(pthis), pthis, "request_token_endpoint", sizeof("request_token_endpoint") - 1, req_api TSRMLS_CC);
	oauth_provider_remove_required_param(sop->required_params, "oauth_token");
}
/* }}} */

/* {{{ proto void OAuthProvider::checkOAuthRequest(string url [, string request_method]) */
SOP_METHOD(checkOAuthRequest)
{
	zval *retval = NULL, **param, *pthis, *is_req_token_api, *token_secret, *consumer_secret, *req_signature, *sig_method;
	php_oauth_provider *sop;
	ulong missing_param_count = 0, mp_count = 1;
	char additional_info[512] = "", *http_verb = NULL, *uri = NULL, *sbs = NULL, *signature = NULL, *signature_encoded = NULL;
	HashPosition hpos;
	HashTable *sbs_vars = NULL;
	int http_verb_len = 0, uri_len = 0;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os|s", &pthis, oauthprovider, &uri, &uri_len, &http_verb, &http_verb_len)==FAILURE) {
		return;
	}

	sop = fetch_sop_object(pthis TSRMLS_CC);

	if(!http_verb_len) {
		http_verb = oauth_provider_get_http_verb(TSRMLS_C);
	}

	if(!http_verb) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "Failed to detect HTTP method, set a HTTP method via OAuthProvider::checkOAuthRequest()");
		return;
	}

	/* if we are in an API which issues a request token, there are is no token handler called */
	is_req_token_api = zend_read_property(Z_OBJCE_P(pthis), pthis, "request_token_endpoint", sizeof("request_token_endpoint") - 1, 1 TSRMLS_CC);

	ALLOC_HASHTABLE(sbs_vars);
	zend_hash_init(sbs_vars, 0, NULL, ZVAL_PTR_DTOR, 0);

	/* XXX should implement a method which lets the caller override POST/GET/Authorization vars used here, so something like OAuthProvider::setParam($name, $val) which updates the sop->oauth_params hash */
	if(PG(http_globals)[TRACK_VARS_GET]) {
		zval *tmp_copy;
		zend_hash_merge(sbs_vars, HASH_OF(PG(http_globals)[TRACK_VARS_GET]), (copy_ctor_func_t)zval_add_ref, (void *)&tmp_copy, sizeof(zval *), 0);
	}
	if(PG(http_globals)[TRACK_VARS_POST]) {
		zval *tmp_copy;
		zend_hash_merge(sbs_vars, HASH_OF(PG(http_globals)[TRACK_VARS_POST]), (copy_ctor_func_t)zval_add_ref, (void *)&tmp_copy, sizeof(zval *), 0);
	}
	if(zend_hash_num_elements(sop->oauth_params)) {
		zval *tmp_copy;
		zend_hash_merge(sbs_vars, sop->oauth_params, (copy_ctor_func_t)zval_add_ref, (void *)&tmp_copy, sizeof(zval *), 0);
	}
	zend_hash_internal_pointer_reset_ex(sbs_vars, &hpos);

	/* set the standard stuff present in every request if its found in sbs_vars, IE if we find oauth_consumer_key, set $oauth->consumer_key */
	oauth_provider_set_std_params(pthis, sbs_vars TSRMLS_CC);

	oauth_provider_check_required_params(sop->required_params, sbs_vars, sop->missing_params TSRMLS_CC);

	missing_param_count = zend_hash_num_elements(sop->missing_params);
	if(missing_param_count) {
		zend_hash_internal_pointer_reset_ex(sop->missing_params, &hpos);
		do {
			if(zend_hash_get_current_data_ex(sop->missing_params, (void **)&param, &hpos)==SUCCESS) {
				snprintf(additional_info, 512, "%s%s%s", additional_info, Z_STRVAL_PP(param), (missing_param_count > 1 && missing_param_count!=mp_count++) ? "%26" : "");
			}
		} while(zend_hash_move_forward_ex(sop->missing_params, &hpos)==SUCCESS);
		soo_handle_error(NULL, OAUTH_PARAMETER_ABSENT, "Missing required parameters", NULL, additional_info TSRMLS_CC);
		FREE_ARGS_HASH(sbs_vars);
		return;
	}

	sig_method = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE_METHOD, sizeof(OAUTH_PROVIDER_SIGNATURE_METHOD) - 1, 1 TSRMLS_CC);
	if(!sig_method || !Z_STRLEN_P(sig_method) || (strcasecmp(Z_STRVAL_P(sig_method), "HMAC-SHA1") && strcasecmp(Z_STRVAL_P(sig_method), "HMAC_SHA1"))) {
		soo_handle_error(NULL, OAUTH_SIGNATURE_METHOD_REJECTED, "Unknown signature method", NULL, NULL TSRMLS_CC);
		return;
	}

	retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TSNONCE_CB);

	convert_to_long(retval);
	if(Z_LVAL_P(retval)!=OAUTH_OK) {
		soo_handle_error(NULL, Z_LVAL_P(retval), "Invalid nonce/timestamp combination", NULL, additional_info TSRMLS_CC);
		zval_ptr_dtor(&retval);
		FREE_ARGS_HASH(sbs_vars);
		return;
	}
	zval_ptr_dtor(&retval);

	retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_CONSUMER_CB);
	convert_to_long(retval);
	if(Z_LVAL_P(retval)!=OAUTH_OK) {
		soo_handle_error(NULL, Z_LVAL_P(retval), "Invalid consumer key", NULL, additional_info TSRMLS_CC);
		zval_ptr_dtor(&retval);
		FREE_ARGS_HASH(sbs_vars);
		return;
	}
	zval_ptr_dtor(&retval);

	if(!Z_BVAL_P(is_req_token_api)) {
		retval = oauth_provider_call_cb(INTERNAL_FUNCTION_PARAM_PASSTHRU, OAUTH_PROVIDER_TOKEN_CB);

		convert_to_long(retval);
		if(Z_LVAL_P(retval)!=OAUTH_OK) {
			soo_handle_error(NULL, Z_LVAL_P(retval), "Invalid token", NULL, additional_info TSRMLS_CC);
			zval_ptr_dtor(&retval);
			FREE_ARGS_HASH(sbs_vars);
			return;
		}
		zval_ptr_dtor(&retval);
	}

	/* now for the signature stuff */
	sbs = oauth_generate_sig_base(NULL, http_verb, uri, sbs_vars, NULL TSRMLS_CC);

	consumer_secret = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_CONSUMER_SECRET, sizeof(OAUTH_PROVIDER_CONSUMER_SECRET) - 1, 1 TSRMLS_CC);
	if(!Z_BVAL_P(is_req_token_api)) {
		token_secret = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_TOKEN_SECRET, sizeof(OAUTH_PROVIDER_TOKEN_SECRET) - 1, 1 TSRMLS_CC);
		signature = soo_sign_hmac(NULL, sbs, consumer_secret ? Z_STRVAL_P(consumer_secret) : "", token_secret ? Z_STRVAL_P(token_secret) : "" TSRMLS_CC);
	} else {
		signature = soo_sign_hmac(NULL, sbs, Z_STRVAL_P(consumer_secret), NULL TSRMLS_CC);
	}

	signature_encoded = oauth_url_encode(signature, strlen(signature));

	req_signature = zend_read_property(Z_OBJCE_P(pthis), pthis, OAUTH_PROVIDER_SIGNATURE, sizeof(OAUTH_PROVIDER_SIGNATURE) - 1, 1 TSRMLS_CC);
	if(!Z_STRLEN_P(req_signature) || strcmp(signature_encoded, Z_STRVAL_P(req_signature))) {
		soo_handle_error(NULL, OAUTH_INVALID_SIGNATURE, "Signatures do not match", NULL, sbs TSRMLS_CC);
	}

	efree(sbs);
	efree(signature);
	efree(signature_encoded);
	FREE_ARGS_HASH(sbs_vars);
}
/* }}} */

/* {{{ proto void OAuthProvider::addRequiredParameter(string $required_param) */
SOP_METHOD(addRequiredParameter)
{
	zval *pthis;
	char *required_param;
	php_oauth_provider *sop;
	ulong req_param_len;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &pthis, oauthprovider, &required_param, &req_param_len)==FAILURE) {
		return;
	}
	
	sop = fetch_sop_object(pthis TSRMLS_CC);

	if(oauth_provider_add_required_param(sop->required_params, required_param)==SUCCESS) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto void OAuthProvider::removeRequiredParameter(string $required_param) */
SOP_METHOD(removeRequiredParameter)
{
	zval *pthis;
	char *required_param;
	php_oauth_provider *sop;
	ulong req_param_len;

	if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &pthis, oauthprovider, &required_param, &req_param_len)==FAILURE) {
		return;
	}
	
	sop = fetch_sop_object(pthis TSRMLS_CC);

	if(oauth_provider_remove_required_param(sop->required_params, required_param)==SUCCESS) {
		RETURN_TRUE;
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ proto void OAuthProvider::reportProblem(Exception $e) */
SOP_METHOD(reportProblem)
{
	zval *exception, *code, *sbs, *missing_params;
	zend_class_entry *ex_ce;
	zend_bool out_malloced = 0;
	char *out, *tmp_out, *http_header_line;
	size_t pr_len;
	ulong lcode;
	uint http_code;
	sapi_header_line ctr = {0};

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 2)
	ex_ce = zend_exception_get_default();
#else
	ex_ce = zend_exception_get_default(TSRMLS_C);
#endif

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &exception, ex_ce)==FAILURE) {
		return;
	}

	/* XXX good candidate for refactoring */
	code = zend_read_property(Z_OBJCE_P(exception), exception, "code", sizeof("code") - 1, 1 TSRMLS_CC);
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
			sbs = zend_read_property(Z_OBJCE_P(exception), exception, "additionalInfo", sizeof("additionalInfo") - 1, 1 TSRMLS_CC);
			if(sbs) {
				convert_to_string_ex(&sbs);
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
			missing_params = zend_read_property(Z_OBJCE_P(exception), exception, "additionalInfo", sizeof("additionalInfo") - 1, 1 TSRMLS_CC);
			if(missing_params) {
				convert_to_string_ex(&missing_params);
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

	ZVAL_STRINGL(return_value, out, strlen(out), 1);

	if(http_code==OAUTH_ERR_BAD_REQUEST) {
		http_header_line = "HTTP/1.1 400 Bad Request";
	} else {
		http_header_line = "HTTP/1.1 401 Unauthorized";
	}

	ctr.line = http_header_line;
	ctr.line_len = strlen(http_header_line);
	ctr.response_code = http_code;

	sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);

	if(out_malloced) {
		efree(out);
	}
}
/* }}} */

static void oauth_provider_free_storage(void *obj TSRMLS_DC) /* {{{ */
{
	php_oauth_provider *sop;

	sop = (php_oauth_provider *)obj;

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
	if (sop->zo.guards) {
		zend_hash_destroy(sop->zo.guards);
		FREE_HASHTABLE(sop->zo.guards);
	}
	if (sop->zo.properties) {
		zend_hash_destroy(sop->zo.properties);
		FREE_HASHTABLE(sop->zo.properties);
	}
#else
	zend_object_std_dtor(&sop->zo TSRMLS_CC);
#endif

	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->consumer_handler);
	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->token_handler);
	OAUTH_PROVIDER_FREE_FCALL_INFO(sop->tsnonce_handler);
	FREE_ARGS_HASH(sop->missing_params);
	FREE_ARGS_HASH(sop->oauth_params);
	FREE_ARGS_HASH(sop->required_params);
	efree(sop);
}
/* }}} */

static zend_object_value oauth_provider_register(php_oauth_provider *soo TSRMLS_DC) /* {{{ */
{
	zend_object_value rv;

	rv.handle = zend_objects_store_put(soo, (zend_objects_store_dtor_t)zend_objects_destroy_object, oauth_provider_free_storage, NULL TSRMLS_CC);
	rv.handlers = (zend_object_handlers *)&oauth_provider_obj_hndlrs;
	return rv;
}

static php_oauth_provider* oauth_provider_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	php_oauth_provider *nos;

	nos = ecalloc(1, sizeof(php_oauth_provider));

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
	ALLOC_HASHTABLE(nos->zo.properties);
	zend_hash_init(nos->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);

	nos->zo.ce = ce;
	nos->zo.guards = NULL;
#else
	zend_object_std_init(&nos->zo, ce TSRMLS_CC);
#endif

	return nos;
}

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider__construct, 0, 0, 0)
ZEND_ARG_INFO(0, params_array)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_handler, 0, 0, 1)
ZEND_ARG_INFO(0, function_name)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_reportproblem, 0, 0, 1)
ZEND_ARG_INFO(0, oauthexception)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_req_token, 0, 0, 1)
ZEND_ARG_INFO(0, params_array)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_provider_set_req_param, 0, 0, 1)
ZEND_ARG_INFO(0, req_params)
ZEND_END_ARG_INFO()

static zend_function_entry oauth_provider_methods[] = { /* {{{ */
		SOP_ME(__construct,			arginfo_oauth_provider__construct,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
		SOP_ME(consumerHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(tokenHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(timestampNonceHandler,	arginfo_oauth_provider_handler,		ZEND_ACC_PUBLIC)
		SOP_ME(callconsumerHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(calltokenHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(callTimestampNonceHandler,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(checkOAuthRequest,	arginfo_oauth_provider_noparams,		ZEND_ACC_PUBLIC)
		SOP_ME(isRequestTokenEndpoint,	arginfo_oauth_provider_req_token,		ZEND_ACC_PUBLIC)
		SOP_ME(reportProblem,	arginfo_oauth_provider_reportproblem,		ZEND_ACC_PUBLIC|ZEND_ACC_STATIC|ZEND_ACC_FINAL)
		SOP_ME(addRequiredParameter,	arginfo_oauth_provider_set_req_param,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		SOP_ME(removeRequiredParameter,	arginfo_oauth_provider_set_req_param,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL)
		PHP_MALIAS(oauthprovider,	is2LeggedEndpoint, isRequestTokenEndpoint, arginfo_oauth_provider_req_token, ZEND_ACC_PUBLIC)
		{NULL, NULL, NULL}
};

static zend_object_value oauth_provider_create_object(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	php_oauth_provider *oprovider;

	oprovider = oauth_provider_new(ce TSRMLS_CC);
	return oauth_provider_register(oprovider TSRMLS_CC);
}
/* }}} */

extern int oauth_provider_register_class(TSRMLS_D) /* {{{ */
{
	zend_class_entry osce;

	INIT_CLASS_ENTRY(osce, "OAuthProvider", oauth_provider_methods);
	osce.create_object = oauth_provider_create_object;

	oauthprovider = zend_register_internal_class(&osce TSRMLS_CC);
	memcpy(&oauth_provider_obj_hndlrs, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

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

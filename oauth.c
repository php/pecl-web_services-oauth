/*
+----------------------------------------------------------------------+
| See LICENSE file for further copyright information                   |
+----------------------------------------------------------------------+
| Author: John Jawed <jawed@php.net>                                   |
+----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
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
#include "php_oauth.h"
#include "php_variables.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "php_globals.h"
#include "ext/standard/file.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_lcg.h"

#include <curl/curl.h>

#define SO_ME(func, arg_info, flags) PHP_ME(oauth, func, arg_info, flags)
#define SO_MALIAS(func, alias, arg_info, flags) PHP_MALIAS(oauth, func, alias, arg_info, flags)
#define SO_METHOD(func) PHP_METHOD(oauth, func)
#define SO_ADD_SIG(f, b) add_arg_for_req(f,OAUTH_PARAM_SIGNATURE,(char *)b TSRMLS_CC); efree(b);
#define CLEANUP_CURL_AND_FORM(f,h) curl_easy_cleanup(h); \
curl_formfree(f);
#define FREE_ARGS_HASH(a) \
	zend_hash_destroy(args); \
	FREE_HASHTABLE(args);

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

void php_oauth_args_hash_dtor(void *p) {
    zval *param_value = (zval *)p;
    
    if(param_value->value.str.val) {
        efree(param_value->value.str.val);
        param_value->value.str.val = NULL;
    }
    zval_ptr_dtor(&param_value);
}

static PHP_GINIT_FUNCTION(oauth) {
    oauth_globals->soo_exception_ce = NULL;
}

static inline php_so_object *fetch_so_object(zval *obj TSRMLS_DC) {
    return (php_so_object *)zend_object_store_get_object(obj TSRMLS_CC);
} 

static int so_set_response_args(HashTable *hasht,zval *data,zval *retarray TSRMLS_DC) {
    ulong h = zend_hash_func(OAUTH_RAW_LAST_RES,strlen(OAUTH_RAW_LAST_RES)+1);
    if(Z_STRVAL_P(data) && *Z_STRVAL_P(data)) {
#if jawed_0
        /* don't need this till we fully implement error reporting ... */
        if(!onlyraw) {
            zend_hash_quick_update(hasht,OAUTH_ATTR_LAST_RES,strlen(OAUTH_ATTR_LAST_RES)+1,h,&arrayArg,sizeof(zval *),NULL); 
        } else {
            zend_hash_quick_update(hasht,OAUTH_ATTR_LAST_RES,strlen(OAUTH_ATTR_LAST_RES)+1,h,&rawval,sizeof(zval *),NULL); 
            h = zend_hash_func(OAUTH_RAW_LAST_RES,strlen(OAUTH_RAW_LAST_RES)+1);
            zend_hash_quick_update(hasht,OAUTH_RAW_LAST_RES,strlen(OAUTH_RAW_LAST_RES)+1,h,&rawval,sizeof(zval *),NULL); 
        }
        if(!onlyraw) {
        } 
        return data;
#endif
	if(retarray!=NULL) {
		char *res = NULL;
		res = estrndup(Z_STRVAL_P(data), Z_STRLEN_P(data));
		sapi_module.treat_data(PARSE_STRING, res, retarray TSRMLS_CC);
	}
        return zend_hash_quick_update(hasht,OAUTH_RAW_LAST_RES,strlen(OAUTH_RAW_LAST_RES)+1,h,&data,sizeof(zval *),NULL); 
    }
    return FAILURE;
}

static zval *so_set_response_info(HashTable *hasht, zval *info) {
    ulong h = zend_hash_func(OAUTH_ATTR_LAST_RES_INFO,strlen(OAUTH_ATTR_LAST_RES_INFO)+1);
    if(zend_hash_quick_update(hasht,OAUTH_ATTR_LAST_RES_INFO,strlen(OAUTH_ATTR_LAST_RES_INFO)+1,h,&info,sizeof(zval *),NULL)!=SUCCESS) {
        return NULL;
    }
    return info;
}

static void so_object_free_storage(void *obj TSRMLS_DC) {
    php_so_object *soo;
    soo = (php_so_object *) obj;
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 1 && PHP_RELEASE_VERSION > 2) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)
    zend_object_std_dtor(&soo->zo TSRMLS_CC);
#else
    if (soo->zo.guards) {
        zend_hash_destroy(soo->zo.guards);
        FREE_HASHTABLE(soo->zo.guards);
    }

    if (soo->zo.properties) {
        zend_hash_destroy(soo->zo.properties);
        FREE_HASHTABLE(soo->zo.properties);
    }
#endif
    if(soo->properties) {
        zend_hash_destroy(soo->properties);
        FREE_HASHTABLE(soo->properties);
    }
    if(soo->lastresponse.c) {
	smart_str_0(&soo->lastresponse);
	smart_str_free(&soo->lastresponse);
    } 
    efree(obj);
}

static void so_object_dtor(void *object, zend_object_handle handle TSRMLS_DC) {
    php_so_object *soo;
    soo = (php_so_object *) object;
    if(soo->tmp) {
        zval_ptr_dtor(&soo->tmp);
        soo->tmp = NULL;
    }
}

static zend_object_value php_so_register_object(php_so_object *soo TSRMLS_DC) {
    zend_object_value rv;
    rv.handle = zend_objects_store_put(soo, so_object_dtor, (zend_objects_free_object_storage_t)so_object_free_storage, NULL TSRMLS_CC);
    rv.handlers = (zend_object_handlers *) &so_object_handlers;
    return rv;
}

static php_so_object* php_so_object_new(zend_class_entry *ce TSRMLS_DC) {
    php_so_object *nos;
    nos = ecalloc(1, sizeof(php_so_object));
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 1 && PHP_RELEASE_VERSION > 2) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)
    zend_object_std_init(&nos->zo, ce TSRMLS_CC);
#else
    ALLOC_HASHTABLE(nos->zo.properties);
    zend_hash_init(nos->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);

    nos->zo.ce = ce;
    nos->zo.guards = NULL;
#endif
    return nos;
}

ZEND_API zend_object_value new_so_object(zend_class_entry *ce TSRMLS_DC) {
    php_so_object *soo;
    soo = php_so_object_new(ce TSRMLS_CC);
    return php_so_register_object(soo TSRMLS_CC);
}

void soo_handle_error(long errorCode,char *msg,char *response TSRMLS_DC) {
    zval *ex;
    zend_class_entry *dex=zend_exception_get_default(TSRMLS_C),*soox=OAUTH(soo_exception_ce);
    MAKE_STD_ZVAL(ex);
    object_init_ex(ex,soox);
    if(!errorCode) {
        php_error(E_WARNING,"caller did not pass an errorcode!");
    } else {
        zend_update_property_string(dex,ex,"errorMessage",sizeof("errorMessage")-1,msg TSRMLS_CC);
        if(response!=NULL) {
            zend_update_property_string(dex,ex,"lastResponse",sizeof("lastResponse")-1,response TSRMLS_CC);
        }
    }
    zend_update_property_long(dex,ex,"errorCode",sizeof("errorCode")-1,errorCode TSRMLS_CC);
    zend_throw_exception_object(ex TSRMLS_CC);
} 

static unsigned char *soo_hmac_sha1(char *message,zval *cs,zval *ts TSRMLS_DC) {
    zval *args[4],*retval,*func;
    char *tret;
    int ret,retlen;
    unsigned char *result;
    MAKE_STD_ZVAL(retval);
    MAKE_STD_ZVAL(args[0]);
    MAKE_STD_ZVAL(args[1]);
    MAKE_STD_ZVAL(args[2]);
    MAKE_STD_ZVAL(args[3]);
    if(ts!=NULL && Z_STRLEN_P(ts)>0) {
        spprintf(&tret,0,"%s&%s",Z_STRVAL_P(cs),Z_STRVAL_P(ts));
    } else {
        spprintf(&tret,0,"%s&",Z_STRVAL_P(cs));
    }
    ZVAL_STRING(args[0],"sha1",0);
    ZVAL_STRING(args[1],message,0);
    ZVAL_STRING(args[2],tret,0);
    ZVAL_BOOL(args[3],1);
    MAKE_STD_ZVAL(func);
    ZVAL_STRING(func,"hash_hmac",0);
    if(!zend_is_callable(func, 0, NULL OAUTH_IS_CALLABLE_CC)) {
        soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"hmac signature generation failed, is ext/hash installed?",NULL TSRMLS_CC);
        efree(tret);
        return NULL;
    }
    ret = call_user_function(EG(function_table), NULL, func, retval, 4, args TSRMLS_CC);
    result = php_base64_encode((unsigned char *)Z_STRVAL_P(retval),Z_STRLEN_P(retval),&retlen);
    FREE_ZVAL(func);
    zval_ptr_dtor(&retval);
    FREE_ZVAL(args[0]);
    FREE_ZVAL(args[1]);
    FREE_ZVAL(args[2]);
    FREE_ZVAL(args[3]);
    efree(tret);
    return result;
}

/* XXX for auth type, need to make sure that the auth type is actually supported before setting */
static inline int soo_set_property(php_so_object *soo,zval *prop,char *prop_name) {
    size_t prop_len = 0;
    ulong h;
    prop_len = strlen(prop_name);
    h = zend_hash_func(prop_name,prop_len+1);
    return zend_hash_quick_update(soo->properties,prop_name,prop_len+1,h,&prop,sizeof(zval *),NULL);
}


static int soo_set_nonce(php_so_object *soo TSRMLS_DC) {
    void *data_ptr;
    zval *zonc;
    char *uniqid;
    int sec, usec;
    struct timeval tv;

    ulong h = zend_hash_func(OAUTH_ATTR_OAUTH_NONCE,strlen(OAUTH_ATTR_OAUTH_NONCE)+1);
    if(zend_hash_quick_find(soo->properties,OAUTH_ATTR_OAUTH_USER_NONCE,strlen(OAUTH_ATTR_OAUTH_NONCE)+1,h,&data_ptr)==SUCCESS) {
        return soo_set_property(soo,(zval *)data_ptr,OAUTH_ATTR_OAUTH_NONCE);
    }

    /* XXX maybe find a better way to generate a nonce... */
    gettimeofday((struct timeval *) &tv, (struct timezone *) NULL);
    sec = (int) tv.tv_sec;
    usec = (int) (tv.tv_usec % 0x100000);
    spprintf(&uniqid, 0, "%ld%08x%05x%.8f", php_rand(TSRMLS_C), sec, usec, php_combined_lcg(TSRMLS_C) * 10);
    MAKE_STD_ZVAL(zonc);
    ZVAL_STRING(zonc,uniqid,1);
    efree(uniqid);
    return soo_set_property(soo,zonc,OAUTH_ATTR_OAUTH_NONCE);
}

static inline zval **soo_get_property(php_so_object *soo,char *prop_name TSRMLS_DC) {
    size_t prop_len = 0;
    void *data_ptr;
    ulong h;
    if(!strcmp(prop_name,OAUTH_ATTR_OAUTH_NONCE)) {
        if(soo_set_nonce(soo TSRMLS_CC)==FAILURE) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"failed generating nonce",NULL TSRMLS_CC);
            return NULL;
        }
    } 
    prop_len = strlen(prop_name);
    h = zend_hash_func(prop_name,prop_len+1);
    if(zend_hash_quick_find(soo->properties,prop_name,prop_len+1,h,&data_ptr)==SUCCESS) {
        return (zval **)data_ptr;
    }
    return NULL;
}

static char *oauth_url_encode(char *qy) {
    char *urlencoded, *ret;
    int out_len, ret_len;

    urlencoded = php_raw_url_encode(qy, strlen(qy), &out_len);

    if(urlencoded) {
        ret = php_str_to_str_ex(urlencoded, out_len, "%7E", sizeof("%7E")-1, "~", sizeof("~")-1, &ret_len, 0, NULL);
	efree(urlencoded);
        return ret;
    }
	return NULL;
}

#ifdef jawed_0
static int oauth_sort_keys(HashTable *ht) {
    /* zval **old_compare_func;
       zend_fcall_info_cache old_user_compare_fci_cache;

       old_compare_func = BG(user_compare_func_name); 
       old_user_compare_fci_cache = BG(user_compare_fci_cache); 
       BG(user_compare_fci_cache) = empty_fcall_info_cache;

       if(!ht) {
       return NULL;
       }

    // well we know strnatcmp will always be around, right...??? ;-) 
    if (zend_hash_sort(ht, zend_qsort, array_user_key_compare, 0 TSRMLS_CC) == FAILURE) {
    PHP_ARRAY_CMP_FUNC_RESTORE();
    } */
}
#endif

/* This function does not currently care to respect parameter precedence, in the sense that if a common param is defined in POST/GET or Authorization header, the precendence is defined by: OAuth Core 1.0 section 9.1.1 */

static char *generate_sig_base(php_so_object *soo, char *uri,HashTable *post_args,HashTable *extra_args TSRMLS_DC) {
    zval *func,*exret2,*exargs2[2];
    uint cur_key_len,post_cur_key_len;
    ulong num_key,post_num_key;
    unsigned short port = 0;
    zend_bool prepend_amp = FALSE;
    char *query, *cur_key,*uri_query = NULL,*scheme = NULL,*path = NULL,*host = NULL,*arg_key = NULL,*post_cur_key = NULL,*auth_type = NULL,*s_port = NULL, *bufz,*param_value, *sbs_query_part = NULL, *sbs_scheme_part = NULL;
    HashTable *decoded_args;
    zval *current_arg_val,**current_arg_val_ex,**current_value,*zuri;
    void *p_current_value,*p_current_arg_val,*p_current_arg_val_ex;
    php_url *urlparts;
    smart_str sbuf = {0}, squery = {0};

    MAKE_STD_ZVAL(zuri);
    ZVAL_STRING(zuri,uri,0);
    MAKE_STD_ZVAL(func);
    MAKE_STD_ZVAL(exret2);

    urlparts = php_url_parse_ex(Z_STRVAL_P(zuri), Z_STRLEN_P(zuri));
    efree(zuri);
    if(urlparts!=NULL) {
        uri_query = urlparts->query;
        scheme = urlparts->scheme;
        host = urlparts->host;
        path = urlparts->path;
        port = urlparts->port;
        if(!host && !scheme) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid url when trying to build base signature string",NULL TSRMLS_CC);
            php_url_free(urlparts);
            return NULL;
        }
        smart_str_appends(&sbuf,scheme);
        smart_str_appends(&sbuf,"://");
        smart_str_appends(&sbuf,host);
        if(port && (
                    (!strcmp("http",scheme) && OAUTH_HTTP_PORT!=port) ||
                    (!strcmp("https",scheme) && OAUTH_HTTPS_PORT!=port)
                   ) 
          ) {
            spprintf(&s_port,0,"%d",port);
            smart_str_appendc(&sbuf,':');
            smart_str_appends(&sbuf,s_port);
            efree(s_port);
        }
        if(path) {
            smart_str_appends(&sbuf,path);
            smart_str_0(&sbuf);
            if(post_args!=NULL) {
                for(zend_hash_internal_pointer_reset(post_args);zend_hash_get_current_key_ex(post_args,&post_cur_key,&post_cur_key_len,&post_num_key,0,NULL)!=HASH_KEY_NON_EXISTANT;zend_hash_move_forward(post_args)) {
                    if(prepend_amp) {
                        smart_str_appendc(&squery,'&');
                        smart_str_0(&squery);
                    }
                    zend_hash_get_current_data(post_args,&p_current_arg_val);
                    current_arg_val = p_current_arg_val;
                    arg_key = oauth_url_encode(post_cur_key);
                    param_value = oauth_url_encode(Z_STRVAL_P(current_arg_val));
                    smart_str_appends(&squery,arg_key);
                    smart_str_appendc(&squery,'=');
                    smart_str_appends(&squery,param_value);
                    smart_str_0(&squery);
                    efree(arg_key);
                    efree(param_value);
                    prepend_amp = TRUE;
                }
                if(uri_query) {
                    smart_str_appendc(&squery,'&');
                    smart_str_appends(&squery,uri_query);
                    smart_str_0(&squery);
                }
            }
            if(extra_args!=NULL) {
                for(zend_hash_internal_pointer_reset(extra_args);zend_hash_get_current_key_ex(extra_args,&post_cur_key,&post_cur_key_len,&post_num_key,0,NULL)!=HASH_KEY_NON_EXISTANT;zend_hash_move_forward(extra_args)) {
                    if(prepend_amp) {
                        smart_str_appendc(&squery,'&');
                        smart_str_0(&squery);
                    }
                    zend_hash_get_current_data(extra_args,&p_current_arg_val_ex);
                    current_arg_val_ex = p_current_arg_val_ex;
                    arg_key = oauth_url_encode(post_cur_key);
                    param_value = oauth_url_encode(Z_STRVAL_PP(current_arg_val_ex));
                    smart_str_appends(&squery,arg_key);
                    smart_str_appendc(&squery,'=');
                    smart_str_appends(&squery,param_value);
                    smart_str_0(&squery);
                    efree(arg_key);
                    efree(param_value);
                }
            }
            MAKE_STD_ZVAL(exargs2[0]);
            array_init(exargs2[0]);
            query = estrdup(squery.c);
            sapi_module.treat_data(PARSE_STRING, query, exargs2[0] TSRMLS_CC);
            smart_str_free(&squery);
            ZVAL_STRING(func,"uksort",0);
            MAKE_STD_ZVAL(exargs2[1]);
            ZVAL_STRING(exargs2[1],"strnatcmp",0);
            /* now the extra args */
            call_user_function(EG(function_table), NULL, func, exret2, 2, exargs2 TSRMLS_CC);
            zval_ptr_dtor(&exret2);
            smart_str_free(&squery);
            if(Z_TYPE_P(exargs2[0])==IS_ARRAY) {
                /* time to re-invent the query */
                if(HASH_OF(exargs2[0])) {
                    decoded_args = HASH_OF(exargs2[0]);
                    prepend_amp = FALSE;
                    for(zend_hash_internal_pointer_reset(decoded_args);zend_hash_get_current_key_ex(decoded_args,&cur_key,&cur_key_len,&num_key,0,NULL)!=HASH_KEY_NON_EXISTANT;zend_hash_move_forward(decoded_args)) {
                        if(prepend_amp) {
                            smart_str_appendc(&squery,'&');
                        }
                        zend_hash_get_current_data(decoded_args,&p_current_value);
                        current_value = p_current_value;
                        if(Z_STRLEN_PP(current_value)>0) {
                            arg_key = oauth_url_encode(cur_key);
                            param_value = oauth_url_encode(Z_STRVAL_PP(current_value));
                            smart_str_appends(&squery,arg_key);
                            smart_str_appendc(&squery,'=');
                            smart_str_appends(&squery,param_value);
                            smart_str_0(&squery);
                            efree(arg_key);
                            efree(param_value);
                            prepend_amp = TRUE;
                        }
                    }
                } else {
                    soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"was not able to get oauth parameters!",NULL TSRMLS_CC);
                }
            }
            FREE_ZVAL(func);
            zval_ptr_dtor(&exargs2[0]);
            FREE_ZVAL(exargs2[1]);
            auth_type = Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));
            sbs_query_part = oauth_url_encode(squery.c);
            sbs_scheme_part = oauth_url_encode(sbuf.c);
            if(!strcmp(auth_type,OAUTH_AUTH_TYPE_FORM)) {
                spprintf(&bufz,0,"POST&%s&%s",sbs_scheme_part,sbs_query_part);
            } else if(!strcmp(auth_type,OAUTH_AUTH_TYPE_URI) || !strcmp(auth_type,OAUTH_AUTH_TYPE_AUTHORIZATION)) {
                spprintf(&bufz,0,"GET&%s&%s",sbs_scheme_part,sbs_query_part);
            } else {
                soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid auth type",NULL TSRMLS_CC);
                return NULL;
            }
            efree(sbs_query_part);
            efree(sbs_scheme_part);
            smart_str_free(&sbuf);
            smart_str_free(&squery);
        }
        php_url_free(urlparts);
#ifdef PHP_OAUTH_DEBUG
        fprintf(stderr,"Signature Base String: %s\n",bufz);
#endif
        return bufz;
    } else {
        return NULL;
    }
    return NULL;
}

/* {{{ proto string oauth_urlencode(string uri)
   URI encoding according to RFC 3986, note: is not utf8 capable until the underlying phpapi is */
PHP_FUNCTION(oauth_urlencode) { 
    int uri_len;
    char *uri;

    if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &uri, &uri_len) == FAILURE) {
        return;
    }

    if(uri_len < 1) {
        soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid uri length (0)",NULL TSRMLS_CC);
        RETURN_NULL();
    }
    RETURN_STRING(oauth_url_encode(uri),1);
}

/* }}} */

/* only hmac-sha1 is supported at the moment, still need to lay down the ground work for supporting plaintext and others, though this should be relatively straight forward */

/* {{{ proto void OAuth::__construct(string consumer_key, string consumer_secret [, string signature_method, [, string auth_type ]])
   Instantiate a new OAuth object */
SO_METHOD(__construct) {
    HashTable *hasht;
    char *ck,*cs,*sig_method = NULL,*auth_method = NULL;
    zval *zck,*zcs,*zsm,*zam,*zver,*zsoo = NULL;
    int ck_len, cs_len,sig_method_len = 0,auth_method_len = 0;
    php_so_object *soo;
    zend_class_entry soo_ex_ce;

    if(curl_global_init(CURL_GLOBAL_ALL)!=CURLE_OK) {
        RETURN_NULL();
    } 

    if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss|ss", &zsoo, so_class_entry, &ck, &ck_len, &cs, &cs_len, &sig_method, &sig_method_len, &auth_method, &auth_method_len)==FAILURE) {
	RETURN_FALSE;
    }

    soo = fetch_so_object(getThis() TSRMLS_CC);
    TSRMLS_SET_CTX(soo->thread_ctx);

    if(sig_method_len<1) {
        sig_method = OAUTH_AUTH_TYPE_AUTHORIZATION;
    }
    if(auth_method_len<1) {
        auth_method = OAUTH_SIG_METHOD_HMACSHA1;
    }
    INIT_CLASS_ENTRY(soo_ex_ce,"OAuthException",NULL);
    OAUTH(soo_exception_ce) = zend_register_internal_class_ex(&soo_ex_ce,zend_exception_get_default(TSRMLS_C),NULL TSRMLS_CC);
    zend_declare_property_null(OAUTH(soo_exception_ce),"errorCode",sizeof("errorCode")-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(OAUTH(soo_exception_ce),"errorMessage",sizeof("errorMessage")-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(OAUTH(soo_exception_ce),"lastResponse",sizeof("lastResponse")-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    if(soo->properties) {
        zend_hash_clean(soo->properties);
        hasht = soo->properties;
    } else {
        ALLOC_HASHTABLE(hasht);
        zend_hash_init(hasht, 0, NULL, ZVAL_PTR_DTOR, 0);
        soo->properties = hasht;
    }
    soo->lastresponse.c = NULL;
    MAKE_STD_ZVAL(zck);
    ZVAL_STRING(zck,ck,1);
    if(soo_set_property(soo,zck,OAUTH_ATTR_CONSUMER_KEY)!=SUCCESS) {
        RETURN_NULL();
    }
    if(cs_len>0) {
        MAKE_STD_ZVAL(zcs);
        ZVAL_STRING(zcs,oauth_url_encode(cs),0);
        if(soo_set_property(soo,zcs,OAUTH_ATTR_CONSUMER_SECRET)!=SUCCESS) {
            RETURN_NULL();
        }
    }
    MAKE_STD_ZVAL(zsm);
    ZVAL_STRING(zsm,sig_method,1);
    if(soo_set_property(soo,zsm,OAUTH_ATTR_SIGMETHOD)!=SUCCESS) {
        RETURN_NULL();
    }
    MAKE_STD_ZVAL(zam);
    ZVAL_STRING(zam,auth_method,1);
    if(soo_set_property(soo,zam,OAUTH_ATTR_AUTHMETHOD)!=SUCCESS) {
        RETURN_NULL();
    }
    MAKE_STD_ZVAL(zver);
    ZVAL_STRING(zver,OAUTH_DEFAULT_VERSION,1);
    if(soo_set_property(soo,zver,OAUTH_ATTR_OAUTH_VERSION)) {
        RETURN_NULL();
    } 
}

/* }}} */

static size_t soo_read_response(void *ptr,size_t size,size_t nmemb, void *userp) {
    uint relsize;
    php_so_object *soo = (php_so_object *)userp;
    relsize = size*nmemb;
    TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);
    smart_str_appendl(&soo->lastresponse,ptr,relsize);
    return relsize;
}

static size_t read_header(void *ptr,size_t size,size_t nmemb,void *data) {
#if jawed_0
    char *header = (char *)ptr;
    size_t clen = strlen(header);
    /* Check for WWW-Authenticate only...might be a better way to do this */
    if(clen>23 && !strncasecmp("WWW-Authenticate: OAuth",header,23)) {
    } /* else if(clen>11 && !strncmp("Content-Type: ",header,13)) {
         for(;*header!='\0';*header++) {
         if(*header==':') {
       *header++; // ok two more
       *header++;
       }
       }
       } */
#endif
    return nmemb*size;
}

static CURLcode make_req(php_so_object *soo,char *url,HashTable *ht TSRMLS_DC) {
    CURLcode cres,ctres,crres;
    CURL *curl;
    struct curl_httppost *formdata = NULL;
    struct curl_httppost *lastptr = NULL;
    long    l_code,response_code;
    double  d_code;
    zval *info,*zret,*kcur;
    zend_bool prepend_amp = FALSE, prepend_comma = FALSE;
    char *s_code,*cur,*cur_key,*content_type = NULL,*bufz = NULL,*auth_type = NULL, *param_name = NULL, *param_val = NULL;
    uint cur_key_len;
    ulong num_key;
    struct curl_slist *auth_header = NULL;
    void *p_cur,*p_kcur;
    smart_str surl = {0}, sheader = {0};

    auth_type = Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_AUTHMETHOD TSRMLS_CC));
    curl = curl_easy_init();
    if(!strcmp(auth_type,OAUTH_AUTH_TYPE_FORM)) {
        for(zend_hash_internal_pointer_reset(ht);zend_hash_get_current_data(ht,&p_cur)==SUCCESS;zend_hash_move_forward(ht)) {
            cur = Z_STRVAL_P((zval *)p_cur);
            zend_hash_get_current_key_ex(ht,&cur_key,&cur_key_len,&num_key,0,NULL);
            curl_formadd(&formdata,&lastptr,CURLFORM_COPYNAME,cur_key,CURLFORM_COPYCONTENTS,cur,CURLFORM_END);
        }
        curl_easy_setopt(curl,CURLOPT_HTTPPOST,formdata);
        curl_easy_setopt(curl,CURLOPT_URL,url);
    } else if(!strcmp(auth_type,OAUTH_AUTH_TYPE_URI)) {
        smart_str_appends(&surl,url);
        if(strstr(url,"?")==NULL) {
            smart_str_appendc(&surl,'?');
        } else {
            smart_str_appendc(&surl,'&');
	}
        for(zend_hash_internal_pointer_reset(ht);zend_hash_get_current_data(ht,&p_kcur)==SUCCESS;zend_hash_move_forward(ht)) {
            if(prepend_amp) {
                smart_str_appendc(&surl,'&');
            }
            kcur = p_kcur;
            zend_hash_get_current_key_ex(ht,&cur_key,&cur_key_len,&num_key,0,NULL);
            param_name = oauth_url_encode(cur_key);
            param_val = oauth_url_encode(Z_STRVAL_P(kcur));
            smart_str_appends(&surl,param_name);
            smart_str_appendc(&surl,'=');
            smart_str_appends(&surl,param_val);
            efree(param_name);
            efree(param_val);
            prepend_amp = TRUE;
        }
        smart_str_0(&surl);
        curl_easy_setopt(curl,CURLOPT_URL,surl.c);
        smart_str_free(&surl);
    } else if(!strcmp(auth_type,OAUTH_AUTH_TYPE_AUTHORIZATION)) {
        smart_str_appends(&sheader,"Authorization: OAuth ");
        smart_str_0(&sheader);
        for(zend_hash_internal_pointer_reset(ht);zend_hash_get_current_data(ht,&p_kcur)==SUCCESS;zend_hash_move_forward(ht)) {
            kcur = p_kcur;
            zend_hash_get_current_key_ex(ht,&cur_key,&cur_key_len,&num_key,0,NULL);
            if(!strncmp(OAUTH_PARAM_PREFIX,cur_key,OAUTH_PARAM_PREFIX_LEN)) {
                if(prepend_comma) {
                    smart_str_appendc(&sheader,',');
                    smart_str_0(&sheader);
                }
                param_name = oauth_url_encode(cur_key);
                param_val = oauth_url_encode(Z_STRVAL_P(kcur));
                smart_str_appends(&sheader,param_name);
                smart_str_appendc(&sheader,'=');
                smart_str_appends(&sheader,"\"");
                smart_str_appends(&sheader,param_val);
                smart_str_appends(&sheader,"\"");
                smart_str_0(&sheader);
                efree(param_name);
                efree(param_val);
                prepend_comma = TRUE;
            }
        }
        auth_header = curl_slist_append(auth_header,sheader.c);
        curl_easy_setopt(curl,CURLOPT_HTTPHEADER,auth_header);
        curl_easy_setopt(curl,CURLOPT_URL,url);
        smart_str_free(&sheader);
    }
    curl_easy_setopt(curl,CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,soo_read_response);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,soo);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0);
    curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,read_header);
    curl_easy_setopt(curl,CURLOPT_WRITEHEADER,NULL);
#ifdef PHP_OAUTH_DEBUG
    curl_easy_setopt(curl,CURLOPT_VERBOSE,1);
#endif

    smart_str_0(&soo->lastresponse);
    smart_str_free(&soo->lastresponse);

    cres = curl_easy_perform(curl);
    if(CURLE_OK==cres) {
        ctres = curl_easy_getinfo(curl,CURLINFO_CONTENT_TYPE,&content_type);
        crres = curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&response_code);
        if(CURLE_OK==crres && ctres==CURLE_OK) {
            ALLOC_INIT_ZVAL(info);
            array_init(info);
            CAAL("http_code",response_code);
            if(content_type!=NULL) {
                CAAS("content_type",content_type);
            }
            if(curl_easy_getinfo(curl,CURLINFO_EFFECTIVE_URL,&s_code)==CURLE_OK) {
                CAAS("url",s_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_HEADER_SIZE,&l_code)==CURLE_OK){
                CAAL("header_size",l_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_REQUEST_SIZE,&l_code)==CURLE_OK){
                CAAL("request_size",l_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_FILETIME,&l_code)==CURLE_OK){
                CAAL("filetime",l_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_SSL_VERIFYRESULT,&l_code)==CURLE_OK){
                CAAL("ssl_verify_result",l_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_REDIRECT_COUNT,&l_code)==CURLE_OK){
                CAAL("redirect_count",l_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_TOTAL_TIME,&d_code)==CURLE_OK){
                CAAD("total_time",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_NAMELOOKUP_TIME,&d_code)==CURLE_OK){
                CAAD("namelookup_time",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_CONNECT_TIME,&d_code)==CURLE_OK){
                CAAD("connect_time",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_PRETRANSFER_TIME,&d_code)==CURLE_OK){
                CAAD("pretransfer_time",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_SIZE_UPLOAD,&d_code)==CURLE_OK){
                CAAD("size_upload",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_SIZE_DOWNLOAD,&d_code)==CURLE_OK){
                CAAD("size_download",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_SPEED_DOWNLOAD,&d_code)==CURLE_OK){
                CAAD("speed_download",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_SPEED_UPLOAD,&d_code)==CURLE_OK){
                CAAD("speed_upload",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_CONTENT_LENGTH_DOWNLOAD,&d_code)==CURLE_OK){
                CAAD("download_content_length",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_CONTENT_LENGTH_UPLOAD,&d_code)==CURLE_OK){
                CAAD("upload_content_length",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_STARTTRANSFER_TIME,&d_code)==CURLE_OK){
                CAAD("starttransfer_time",d_code);
            }
            if(curl_easy_getinfo(curl,CURLINFO_REDIRECT_TIME,&d_code)==CURLE_OK){
                CAAD("redirect_time",d_code);
            }
            so_set_response_info(soo->properties,info);
            CLEANUP_CURL_AND_FORM(formdata,curl);
            smart_str_0(&soo->lastresponse);
            /* XXX maybe we should instead check for specific codes, like 40X */
            if(response_code!=200) {
                cres = FAILURE;
                spprintf(&bufz,0,"invalid auth/bad request (got a %d, expected 200)",(int)response_code);
                ALLOC_ZVAL(zret);
                ZVAL_STRING(zret,soo->lastresponse.c,0);
                so_set_response_args(soo->properties,zret,NULL TSRMLS_CC);
                soo_handle_error(response_code,bufz,soo->lastresponse.c TSRMLS_CC);
                //soo_handle_error(response_code,bufz,NULL TSRMLS_CC);
                efree(bufz);
                efree(zret);
            }
        }
    }
    return cres;
}

static int add_arg_for_req(HashTable *ht,const char *arg, char *val TSRMLS_DC) {
    zval *varg;
    ulong h;

    if(!val) {
        char *sarg;
        spprintf(&sarg,0,"error adding parameter to request ('%s')",arg);
        soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,sarg,NULL TSRMLS_CC);
        efree(sarg);
        return FAILURE;
    }
    MAKE_STD_ZVAL(varg);
    ZVAL_STRING(varg,val,1);
    h = zend_hash_func(arg, strlen(arg)+1);
    zend_hash_quick_update(ht, arg, strlen(arg)+1, h, varg, sizeof(zval *), NULL);
    efree(varg);
    return SUCCESS;
}

static void make_standard_query(HashTable *ht,php_so_object *soo TSRMLS_DC) {
    char *tb;
    time_t now;

    now = time(NULL);
    /* XXX allow caller to set timestamp, if none set, then default to "now" */
    spprintf(&tb,0,"%d",(int)now);
    add_arg_for_req(ht,OAUTH_PARAM_CONSUMER_KEY,Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_CONSUMER_KEY TSRMLS_CC)) TSRMLS_CC);
    add_arg_for_req(ht,OAUTH_PARAM_SIGNATURE_METHOD,Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_SIGMETHOD TSRMLS_CC)) TSRMLS_CC);
    add_arg_for_req(ht,OAUTH_PARAM_NONCE,Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_OAUTH_NONCE TSRMLS_CC)) TSRMLS_CC);
    add_arg_for_req(ht,OAUTH_PARAM_TIMESTAMP,tb TSRMLS_CC);
    add_arg_for_req(ht,OAUTH_PARAM_VERSION,Z_STRVAL_PP(soo_get_property(soo,OAUTH_ATTR_OAUTH_VERSION TSRMLS_CC)) TSRMLS_CC); 
    efree(tb);
}

/* {{{ proto array OAuth::getRequestToken(string request_token_url)
   Get request token */
SO_METHOD(getRequestToken) {
    php_so_object *soo;
    int url_len = 0;
    zval **cs = NULL, *zret = NULL, *zsoo;
    char *sbs, *url;
    unsigned char *sig = NULL;
    HashTable *args;
    CURLcode retcode;

    {
        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &zsoo, so_class_entry, &url, &url_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(url_len<1) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid access token url length",NULL TSRMLS_CC);
            RETURN_FALSE;
        }
        ALLOC_HASHTABLE(args);
        zend_hash_init(args, 0, NULL, php_oauth_args_hash_dtor, 0);
        make_standard_query(args,soo TSRMLS_CC);
        sbs = generate_sig_base(soo,url,args,NULL TSRMLS_CC);
        if(!sbs) {
            FREE_ARGS_HASH(args);
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid url, unable to generate signature base string",NULL TSRMLS_CC);
            RETURN_FALSE;
        }
        cs = soo_get_property(soo,OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
        SEPARATE_ZVAL(cs);
        sig = soo_hmac_sha1(sbs,*cs,NULL TSRMLS_CC);
        efree(sbs);
        if(!sig) {
			FREE_ARGS_HASH(args);
            RETURN_NULL();
            return;
        }

        SO_ADD_SIG(args,sig);

        smart_str_free(&soo->lastresponse);
        retcode = make_req(soo,url,args TSRMLS_CC);
        smart_str_0(&soo->lastresponse); 
        FREE_ARGS_HASH(args);
        if(retcode==FAILURE) {
            RETURN_NULL();
        } else {
            if(retcode==CURLE_OK && soo->lastresponse.c) {
                array_init(return_value);
                ALLOC_ZVAL(zret);
                ZVAL_STRING(zret,soo->lastresponse.c,0);
                so_set_response_args(soo->properties,zret,return_value TSRMLS_CC);
                efree(zret);
            }
        } 
    }
}

/* }}} */

/* {{{ proto bool OAuth::setVersion(string version)
   Set oauth_version for requests (default 1.0) */
SO_METHOD(setVersion) {
    php_so_object *soo;
    int ver_len = 0;
    char *vers;
    zval *zver,*zsoo = NULL;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &zsoo, so_class_entry, &vers, &ver_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        if(ver_len < 1) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid version",NULL TSRMLS_CC);
            RETURN_NULL();
        }

        MAKE_STD_ZVAL(zver);
        ZVAL_STRING(zver,vers,1);
        if(soo_set_property(soo,zver,OAUTH_ATTR_OAUTH_VERSION)) {
            RETURN_TRUE;
        } {
            RETURN_FALSE;
        }
    }
}

/* }}} */

/* {{{ proto bool OAuth::setAuthType(string auth_type)
   Set the manner in which to send oauth parameters */
SO_METHOD(setAuthType) {
    php_so_object *soo;
    int auth_len;
    char *auth;
    zval *zauth,*zsoo = NULL;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &zsoo, so_class_entry, &auth, &auth_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        /* XXX check to see if we actually support the type rather than just the length */
        if(auth_len < 1) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid auth type",NULL TSRMLS_CC);
            RETURN_NULL();
        }

        MAKE_STD_ZVAL(zauth);
        ZVAL_STRING(zauth,auth,1);
        if(soo_set_property(soo,zauth,OAUTH_ATTR_AUTHMETHOD)==SUCCESS) {
            RETURN_TRUE;
        } {
            RETURN_FALSE;
        }
    }
}

/* }}} */

/* {{{ proto bool OAuth::setNonce(string nonce)
   Set oauth_nonce for subsequent requests, if none is set a random nonce will be generated using uniqid */
SO_METHOD(setNonce) {
    php_so_object *soo;
    int nonce_len;
    char *nonce;
    zval *zonce,*zsoo = NULL;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os", &zsoo, so_class_entry, &nonce, &nonce_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        if(nonce_len < 1) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid nonce",NULL TSRMLS_CC);
            RETURN_NULL();
        }

        MAKE_STD_ZVAL(zonce);
        ZVAL_STRING(zonce,nonce,1);
        if(soo_set_property(soo,zonce,OAUTH_ATTR_OAUTH_USER_NONCE)) {
            RETURN_TRUE;
        } {
            RETURN_FALSE;
        }
    }
}

/* }}} */

/* {{{ proto bool OAuth::setToken(string token, string token_secret)
   Set a request or access token and token secret to be used in subsequent requests */
SO_METHOD(setToken) {
    php_so_object *soo;
    int token_len,token_secret_len;
    char *token,*token_secret;
    zval *t,*ts,*zsoo = NULL;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os|s", &zsoo, so_class_entry, &token, &token_len, &token_secret, &token_secret_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        if(token_len < 1) {
            token = "";
        }

        MAKE_STD_ZVAL(t);
        ZVAL_STRING(t,token,1);
        soo_set_property(soo,t,OAUTH_ATTR_TOKEN);

        if(token_secret_len > 1) {
            MAKE_STD_ZVAL(ts);
            ZVAL_STRING(ts,token_secret,1);
            soo_set_property(soo,ts,OAUTH_ATTR_TOKEN_SECRET);
        }
        RETURN_TRUE;
    }
}

/* }}} */

/* {{{ proto bool OAuth::fetch(string protected_resource_url [, array extra_parameters])
   fetch a protected resource, pass in extra_parameters (array(name => value)) */
SO_METHOD(fetch) {
    php_so_object *soo;
    int fetchurl_len;
    char *fetchurl,*req_cur_key = NULL, *sbs = NULL;
    unsigned char *sig = NULL;
    zval **token = NULL,**cs,*request_args = NULL,*ts = NULL,**token_secret = NULL,**p_current_req_val,*zsoo = NULL;
    uint req_cur_key_len;
    ulong req_num_key;
    HashTable *args = NULL,*rargs = NULL;
    CURLcode retcode;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os|z", &zsoo, so_class_entry, &fetchurl, &fetchurl_len, &request_args)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        if(fetchurl_len < 1) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid protected resource url length",NULL TSRMLS_CC);
            RETURN_NULL();
            return;
        }

        ALLOC_HASHTABLE(args);
        zend_hash_init(args, 0, NULL, php_oauth_args_hash_dtor, 0);

        make_standard_query(args,soo TSRMLS_CC);
        if(request_args) {
            rargs = HASH_OF(request_args);
        }
        token = soo_get_property(soo,OAUTH_ATTR_TOKEN TSRMLS_CC);
        if(token) {
            add_arg_for_req(args,OAUTH_PARAM_TOKEN,Z_STRVAL_PP(token) TSRMLS_CC);
        }
        sbs = generate_sig_base(soo,fetchurl,args,rargs TSRMLS_CC);
        if(!sbs) {
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid protected resource url, unable to generate signature base string",NULL TSRMLS_CC);
            RETURN_FALSE;
        }
        cs = soo_get_property(soo,OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
        SEPARATE_ZVAL(cs);
        token_secret = soo_get_property(soo,OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
        if(token_secret && Z_STRLEN_PP(token_secret)>0) {
            ts = *token_secret;
        }
        sig = soo_hmac_sha1(sbs,*cs,ts TSRMLS_CC);
        efree(sbs);
        if(!sig) {
        	FREE_ARGS_HASH(args);
            RETURN_NULL();
            return;
        }

        SO_ADD_SIG(args,sig);

        if(rargs) {
            for(zend_hash_internal_pointer_reset(rargs);zend_hash_get_current_key_ex(rargs,&req_cur_key,&req_cur_key_len,&req_num_key,0,NULL)!=HASH_KEY_NON_EXISTANT;zend_hash_move_forward(rargs)) {
                zend_hash_get_current_data(rargs,(void **)&p_current_req_val);
                add_arg_for_req(args,req_cur_key,Z_STRVAL_PP(p_current_req_val) TSRMLS_CC);
            }
        }
        smart_str_free(&soo->lastresponse);
        retcode = make_req(soo,fetchurl,args TSRMLS_CC);
        smart_str_0(&soo->lastresponse);
        /* MAKE_STD_ZVAL(zret);
        ZVAL_STRING(zret, soo->lastresponse.c ? soo->lastresponse.c : "", 0);
        so_set_response_args(soo->properties,zret,NULL TSRMLS_CC); */
        //zval_ptr_dtor(&zret);
        FREE_ARGS_HASH(args);
        if(retcode==FAILURE || soo->lastresponse.c==NULL) {
            RETURN_NULL();
        } else {
            if(retcode==CURLE_OK && soo->lastresponse.c) {
                RETURN_TRUE;
            } else {
                RETURN_FALSE;
            }
        }
        RETURN_NULL();
    }
}

/* }}} */

/* {{{ proto array OAuth::getAccessToken(string access_token_url [, string auth_session_handle ])
   Get access token, if the server supports Scalable OAuth pass in the auth_session_handle to refresh the token (http://wiki.oauth.net/ScalableOAuth) */
SO_METHOD(getAccessToken) {
    php_so_object *soo;
    int aturi_len = 0,ash_len = 0;
    char *aturi,*ash,*sbs;
    unsigned char *sig = NULL;
    zval **cs = NULL,**token_secret,*ts = NULL,**token = NULL, *zret = NULL, *zsoo = NULL;
    HashTable *args;
    CURLcode retcode;

    soo = fetch_so_object(getThis() TSRMLS_CC);
    {
        TSRMLS_FETCH_FROM_CTX(soo->thread_ctx);

        if(zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Os|s", &zsoo, so_class_entry, &aturi, &aturi_len, &ash, &ash_len)==FAILURE) {
			RETURN_FALSE;
        }

		soo = fetch_so_object(zsoo TSRMLS_CC);

        ALLOC_HASHTABLE(args);
        zend_hash_init(args, 0, NULL, php_oauth_args_hash_dtor, 0);
        make_standard_query(args,soo TSRMLS_CC);
        if(aturi_len<1) {
            FREE_ARGS_HASH(args);
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"invalid access token url length",NULL TSRMLS_CC);
            RETURN_FALSE;
        }

        if(ash_len>0) {
            add_arg_for_req(args,OAUTH_PARAM_ASH,ash TSRMLS_CC);
        }
        token = soo_get_property(soo,OAUTH_ATTR_TOKEN TSRMLS_CC);
        if(token) {
            add_arg_for_req(args,OAUTH_PARAM_TOKEN,Z_STRVAL_PP(token) TSRMLS_CC);
        }
        sbs = generate_sig_base(soo,aturi,args,NULL TSRMLS_CC);
        if(!sbs) {
            FREE_ARGS_HASH(args);
            soo_handle_error(OAUTH_ERR_INTERNAL_ERROR,"unable to generate signature base string, perhaps the access token url is invalid",NULL TSRMLS_CC);
            RETURN_FALSE;
        }
        cs = soo_get_property(soo,OAUTH_ATTR_CONSUMER_SECRET TSRMLS_CC);
        SEPARATE_ZVAL(cs);
        token_secret = soo_get_property(soo,OAUTH_ATTR_TOKEN_SECRET TSRMLS_CC);
        if(token_secret && Z_STRLEN_PP(token_secret)>0) {
            ts = *token_secret;
        }

        sig = soo_hmac_sha1(sbs,*cs,ts TSRMLS_CC);
        efree(sbs);
        if(!sig) {
            FREE_ARGS_HASH(args);
            RETURN_NULL();
            return;
        }

        SO_ADD_SIG(args,sig);

        smart_str_free(&soo->lastresponse);
        retcode = make_req(soo,aturi,args TSRMLS_CC);
        smart_str_0(&soo->lastresponse);
        FREE_ARGS_HASH(args);
        if(retcode==FAILURE) {
            RETURN_NULL();
        } else {
            if(retcode==CURLE_OK && soo->lastresponse.c) {
                array_init(return_value);
                ALLOC_ZVAL(zret);
                ZVAL_STRING(zret,soo->lastresponse.c,0);
                so_set_response_args(soo->properties,zret,return_value TSRMLS_CC);
                efree(zret);
            }
        } 
    }
}
/* }}} */

/* {{{ proto array OAuth::getLastResponseInfo(void)
   Get information about the last response */
SO_METHOD(getLastResponseInfo) {
    php_so_object *soo;
    void *p_data_ptr;
    zval **data_ptr;
    ulong hf = 0;
    ulong hlen = 0;
    char *hkey = OAUTH_ATTR_LAST_RES_INFO;
    
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	
    soo = fetch_so_object(getThis() TSRMLS_CC);

    hlen = strlen(hkey)+1;
    hf = zend_hash_func(hkey,hlen);
    if(zend_hash_quick_find(soo->properties,hkey,hlen,hf,&p_data_ptr)==SUCCESS) {
        data_ptr = p_data_ptr;
        if(Z_TYPE_PP(data_ptr)==IS_ARRAY) {
            convert_to_array_ex(data_ptr);
        }
        RETURN_ZVAL(*data_ptr,1,0);
    }
    RETURN_NULL();
}

/* }}} */

/* {{{ proto array OAuth::getLastResponse(void)
   Get last response */
SO_METHOD(getLastResponse) {
    php_so_object *soo;
    
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	
    soo = fetch_so_object(getThis() TSRMLS_CC);
    
    if(soo->lastresponse.c) {
		RETURN_STRING(soo->lastresponse.c,1);
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
    if(zend_hash_quick_find(soo->properties,hkey,hlen,hf,&p_data_ptr)==SUCCESS) {
        data_ptr = p_data_ptr;
        RETURN_STRING(Z_STRVAL_P(*data_ptr),0);
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
	ZEND_ARG_INFO(0, extra_parameters)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_oauth_getaccesstoken, 0, 0, 1)
	ZEND_ARG_INFO(0, access_token_url)
	ZEND_ARG_INFO(0, auth_session_handle)
ZEND_END_ARG_INFO()

OAUTH_ARGINFO
ZEND_BEGIN_ARG_INFO(arginfo_oauth__void, 0)
ZEND_END_ARG_INFO()
/* }}} */

static zend_function_entry so_functions[] = {
	SO_ME(__construct,			arginfo_oauth__construct,		ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
	SO_ME(getRequestToken,		arginfo_oauth_getrequesttoken,	ZEND_ACC_PUBLIC)
	SO_ME(getAccessToken,		arginfo_oauth_getaccesstoken,	ZEND_ACC_PUBLIC)
	SO_ME(getLastResponse,		arginfo_oauth__void,			ZEND_ACC_PUBLIC)
	SO_ME(getLastResponseInfo,	arginfo_oauth__void,			ZEND_ACC_PUBLIC)
	SO_ME(setToken,				arginfo_oauth_settoken,			ZEND_ACC_PUBLIC)
	SO_ME(setVersion,			arginfo_oauth_setversion,		ZEND_ACC_PUBLIC)
	SO_ME(setAuthType,			arginfo_oauth_setauthtype,		ZEND_ACC_PUBLIC)
	SO_ME(setNonce,				arginfo_oauth_setnonce,			ZEND_ACC_PUBLIC)
	SO_ME(fetch,				arginfo_oauth_fetch,			ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

PHP_MINIT_FUNCTION(oauth) {
    zend_class_entry soce;
    INIT_CLASS_ENTRY(soce, "OAuth", so_functions);
    soce.create_object = new_so_object;
    so_class_entry = zend_register_internal_class(&soce TSRMLS_CC);
    memcpy(&so_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    REGISTER_STRING_CONSTANT("OAUTH_SIG_METHOD_HMACSHA1",OAUTH_SIG_METHOD_HMACSHA1,CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_AUTHORIZATION",OAUTH_AUTH_TYPE_AUTHORIZATION,CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_URI",OAUTH_AUTH_TYPE_URI,CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("OAUTH_AUTH_TYPE_FORM",OAUTH_AUTH_TYPE_FORM,CONST_CS | CONST_PERSISTENT);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(oauth)
{
    so_class_entry = NULL;
    return SUCCESS;
}

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

/* TODO expose a function for base sig string */
zend_function_entry oauth_functions[] = {
	PHP_FE(oauth_urlencode,		arginfo_oauth_urlencode)
	{ NULL, NULL, NULL }
};

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


/**
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4 noexpandtab
 */

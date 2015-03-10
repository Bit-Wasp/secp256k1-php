/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"

#include <secp256k1.h>

/* If you declare any globals in php_secp256k1.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(secp256k1)
*/

/* True global resources - no need for thread safety here */
static int le_secp256k1;

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("secp256k1.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_secp256k1_globals, secp256k1_globals)
    STD_PHP_INI_ENTRY("secp256k1.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_secp256k1_globals, secp256k1_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Eevery user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_secp256k1_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_secp256k1_compiled)
{
	char *arg = NULL;
	size_t arg_len, len;
	char *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &arg, &arg_len) == FAILURE) {
		return;
	}

	len = spprintf(&strg, 0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "secp256k1", arg);

	RETVAL_STRING(strg, len);
	efree(strg);
}

/* {{{ proto void hello_print(void)
*   Print a message to show how much PHP extensions rock */
PHP_FUNCTION(secp256k1_start)
{
    secp256k1_start(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
    RETURN_TRUE;
}

/* {{{ proto void hello_print(void)
*   Print a message to show how much PHP extensions rock */
PHP_FUNCTION(secp256k1_stop)
{
    secp256k1_stop();
    RETURN_TRUE;
}

/**
* Verify an ECDSA signature.
*
* Returns: 1: correct signature
* 0: incorrect signature
* -1: invalid public key
* -2: invalid signature
*
* In: msg32: the 32-byte message hash being verified (cannot be NULL)
* sig: the signature being verified (cannot be NULL)
* pubkey: the public key to verify with (cannot be NULL)
* Requires starting using SECP256K1_START_VERIFY.
*/
PHP_FUNCTION(secp256k1_ecdsa_verify)
{
   unsigned char *msg32 = (unsigned char *) 0 ;
  int msg32len;
  unsigned char *sig = (unsigned char *) 0 ;
  int siglen ;
  unsigned char *pubkey = (unsigned char *) 0 ;
  int pubkeylen ;
  zval **args[5];
  int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", 
        &msg32, &msg32len,
        &sig, &siglen,
        &pubkey, &pubkeylen
    ) == FAILURE) {
        return;
    }

    result = secp256k1_ecdsa_verify((unsigned char const *)msg32, (unsigned char const *)sig, siglen, (unsigned char const *)pubkey, pubkeylen);

    RETURN_LONG(result);
fail:
  zend_error_noreturn(SWIG_ErrorCode(),"%s",SWIG_ErrorMsg());
}



/* }}} */
/* }}} */
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_secp256k1_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_secp256k1_init_globals(zend_secp256k1_globals *secp256k1_globals)
{
	secp256k1_globals->global_value = 0;
	secp256k1_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(secp256k1)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(secp256k1)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(secp256k1)
{
#if defined(COMPILE_DL_SECP256K1) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(secp256k1)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(secp256k1)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "secp256k1 support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ secp256k1_functions[]
 *
 * Every user visible function must have an entry in secp256k1_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
	PHP_FE(confirm_secp256k1_compiled,	NULL)		/* For testing, remove later. */
        PHP_FE(secp256k1_start, NULL)
        PHP_FE(secp256k1_stop, NULL)
        PHP_FE(secp256k1_ecdsa_verify, NULL)
	PHP_FE_END	/* Must be the last line in secp256k1_functions[] */
};
/* }}} */

/* {{{ secp256k1_module_entry
 */
zend_module_entry secp256k1_module_entry = {
	STANDARD_MODULE_HEADER,
	"secp256k1",
	secp256k1_functions,
	PHP_MINIT(secp256k1),
	PHP_MSHUTDOWN(secp256k1),
	PHP_RINIT(secp256k1),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(secp256k1),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(secp256k1),
	PHP_SECP256K1_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SECP256K1
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(secp256k1)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

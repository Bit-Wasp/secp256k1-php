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
static int le_secp256k1_init = 0;

int init(void) {
    if (le_secp256k1_init == 0) {
        secp256k1_start(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
        le_secp256k1_init = 1;
    }

    return 1;
}

/**
* execute secp256k1_start, automatically happens on first function call that needs it
*  but can be usefull when you're benchmarking
*/
PHP_FUNCTION(secp256k1_init)
{
    init();
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
  init();

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


PHP_MINIT_FUNCTION(secp256k1)
{
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1)
{
	return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1)
{
#if defined(COMPILE_DL_SECP256K1) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}

/* Remove if there's nothing to do at request end */
PHP_RSHUTDOWN_FUNCTION(secp256k1)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(secp256k1)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "secp256k1 support", "enabled");
	php_info_print_table_end();
}

/* {{{ secp256k1_functions[]
 *
 * Every user visible function must have an entry in secp256k1_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
        PHP_FE(secp256k1_init, NULL)
        PHP_FE(secp256k1_ecdsa_verify, NULL)
	PHP_FE_END	/* Must be the last line in secp256k1_functions[] */
};

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

#ifdef COMPILE_DL_SECP256K1
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(secp256k1)
#endif

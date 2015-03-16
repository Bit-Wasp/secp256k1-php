/* $Id$ */

#ifndef PHP_SECP256K1_H
#define PHP_SECP256K1_H

extern zend_module_entry secp256k1_module_entry;
#define phpext_secp256k1_ptr &secp256k1_module_entry

#define PHP_SECP256K1_VERSION "0.1.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#define PHP_SECP256K1_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define PHP_SECP256K1_API __attribute__ ((visibility("default")))
#else
#define PHP_SECP256K1_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_FUNCTION(secp256k1_start);
PHP_FUNCTION(secp256k1_stop);
PHP_FUNCTION(secp256k1_ecdsa_verify);
PHP_FUNCTION(secp256k1_ecdsa_sign);
PHP_FUNCTION(secp256k1_ec_seckey_verify);
PHP_FUNCTION(secp256k1_ec_pubkey_verify);
PHP_FUNCTION(secp256k1_ec_pubkey_create);
PHP_FUNCTION(secp256k1_ec_pubkey_decompress);
PHP_FUNCTION(secp256k1_ec_privkey_import);
PHP_FUNCTION(secp256k1_ec_privkey_export);
PHP_FUNCTION(secp256k1_test_by_reference);

#ifdef ZTS
#define SECP256K1_G(v) ZEND_TSRMG(secp256k1_globals_id, zend_secp256k1_globals *, v)
#ifdef COMPILE_DL_SECP256K1
ZEND_TSRMLS_CACHE_EXTERN();
#endif
#else
#define SECP256K1_G(v) (secp256k1_globals.v)
#endif

#endif	/* PHP_SECP256K1_H */

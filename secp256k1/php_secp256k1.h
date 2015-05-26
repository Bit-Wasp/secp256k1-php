/* $Id$ */
#include <secp256k1.h>

#ifndef PHP_SECP256K1_H
#define PHP_SECP256K1_H

extern zend_module_entry secp256k1_module_entry;
#define phpext_secp256k1_ptr &secp256k1_module_entry

#define PHP_SECP256K1_VERSION "0.1.0"
#define PHP_CTX_STRUCT_RES_NAME "secp256k1_context_t"
typedef struct _php_ctx_struct {
    secp256k1_context_t *ctx;
} php_ctx_struct;

//ZEND_BEGIN_MODULE_GLOBALS(secp256k1)
//    secp256k1_context_t* context;
//ZEND_END_MODULE_GLOBALS(secp256k1)

#ifdef ZTS
# define SECP256K1_G(v) TSRMG(secp256k1_globals_id, zend_secp256k1_globals *, v)
#else
# define SECP256K1_G(v) (secp256k1_globals.v)
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
PHP_FUNCTION(secp256k1_ec_privkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_privkey_tweak_mul);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_mul);

#endif	/* PHP_SECP256K1_H */

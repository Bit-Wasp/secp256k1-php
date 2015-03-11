/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"

#include <secp256k1.h>

PHP_FUNCTION(secp256k1_start) {

    long mode;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
            &mode
            ) == FAILURE) {
        return;
    }

    secp256k1_start(mode);
}

PHP_FUNCTION(secp256k1_stop) {
    secp256k1_stop();
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
PHP_FUNCTION(secp256k1_ecdsa_verify) {
    secp256k1_start(SECP256K1_START_VERIFY);

    unsigned char *msg32 = (unsigned char *) 0;
    int msg32len;
    unsigned char *sig = (unsigned char *) 0;
    int siglen;
    unsigned char *pubkey = (unsigned char *) 0;
    int pubkeylen;
    zval **args[5];
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
            &msg32, &msg32len,
            &sig, &siglen,
            &pubkey, &pubkeylen
            ) == FAILURE)
        return;


    result = secp256k1_ecdsa_verify(msg32, sig, siglen, pubkey, pubkeylen);

    RETURN_LONG(result);
}

/** Verify an ECDSA secret key.
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
PHP_FUNCTION(secp256k1_ec_seckey_verify) {
    unsigned char *seckey;
    int seckeylen;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
            &seckey, &seckeylen
            ) == FAILURE) {
        return;
    }

    result = secp256k1_ec_seckey_verify(seckey);
    RETURN_LONG(result);
}

/** Just validate a public key.
 *  Returns: 1: valid public key
 *           0: invalid public key
 *  In:      pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
 *           pubkeylen: length of pubkey
 */
PHP_FUNCTION(secp256k1_ec_pubkey_verify) {
    secp256k1_start(SECP256K1_START_SIGN);

    unsigned char *pubkey;
    int pubkeylen;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
            &pubkey, &pubkeylen
            ) == FAILURE) {
        return;
    }

    result = secp256k1_ec_pubkey_verify(pubkey, pubkeylen);
    RETURN_LONG(result);
}

PHP_FUNCTION(secp256k1_test_by_reference) {
    zval *parameter;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &parameter) == FAILURE)
        return;

    /* make changes to the parameter */
    ZVAL_LONG(parameter, 10);

    RETURN_TRUE;
}

PHP_FUNCTION(secp256k1_ec_pubkey_create) {
    secp256k1_start(SECP256K1_START_SIGN);

    zval *pubkey;
    zval *pubkeylen;
    unsigned char newpubkey[65];
    int newpubkeylen;
    unsigned char *seckey;
    int seckeylen, compressed, result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzsb",
            &pubkey,
            &pubkeylen,
            &seckey, &seckeylen,
            &compressed
            ) == FAILURE)
        return;

    result = secp256k1_ec_pubkey_create(newpubkey, &newpubkeylen, (unsigned char const *) seckey, (int) compressed);

    ZVAL_STRING(pubkey, newpubkey, 1);
    ZVAL_LONG(pubkeylen, newpubkeylen);

    RETURN_LONG(result);
}

PHP_FUNCTION(secp256k1_ec_pubkey_decompress) {
    zval *pubkey;
    zval *pubkeylen;
    unsigned char *newpubkey;
    int newpubkeylen = 33;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz",
            &pubkey,
            &pubkeylen
            ) == FAILURE) {
        return;
    }

    newpubkey = Z_STRVAL_P(pubkey);
    newpubkeylen = Z_LVAL_P(pubkeylen);
    result = secp256k1_ec_pubkey_decompress(newpubkey, &newpubkeylen);
    if (result == 1) {
        ZVAL_STRING(pubkey, newpubkey, 1);
        ZVAL_LONG(pubkeylen, newpubkeylen);
    }
    RETURN_LONG(result);
}

PHP_MINIT_FUNCTION(secp256k1) {

    REGISTER_LONG_CONSTANT("SECP256K1_START_VERIFY", SECP256K1_START_VERIFY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_START_SIGN", SECP256K1_START_SIGN, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1) {
#if defined(COMPILE_DL_SECP256K1) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    return SUCCESS;
}

/* Remove if there's nothing to do at request end */
PHP_RSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(secp256k1) {
    php_info_print_table_start();
    php_info_print_table_header(2, "secp256k1 support", "enabled");
    php_info_print_table_end();
}

/* {{{ secp256k1_functions[]
 *
 * Every user visible function must have an entry in secp256k1_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
    PHP_FE(secp256k1_start, NULL)
    PHP_FE(secp256k1_stop, NULL)
    PHP_FE(secp256k1_ec_seckey_verify, NULL)
    PHP_FE(secp256k1_ec_pubkey_verify, NULL)
    PHP_FE(secp256k1_ec_pubkey_create, NULL)
    PHP_FE(secp256k1_ec_pubkey_decompress, NULL)
    PHP_FE(secp256k1_ecdsa_verify, NULL)
    PHP_FE(secp256k1_test_by_reference, NULL)
    PHP_FE_END /* Must be the last line in secp256k1_functions[] */
};

zend_module_entry secp256k1_module_entry = {
    STANDARD_MODULE_HEADER,
    "secp256k1",
    secp256k1_functions,
    PHP_MINIT(secp256k1),
    PHP_MSHUTDOWN(secp256k1),
    PHP_RINIT(secp256k1), /* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(secp256k1), /* Replace with NULL if there's nothing to do at request end */
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

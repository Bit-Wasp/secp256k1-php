/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_version.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"
#include "lax_der.h"
#include "zend_exceptions.h"

static zend_class_entry *spl_ce_InvalidArgumentException;

// secp256k1_scratch_space_wrapper embeds the scratch space
// and the context which created it, as the function
// secp256k1_scratch_space_destroy is called in dtor functions
// which have no access to the context otherwise.
typedef struct secp256k1_scratch_space_wrapper {
        secp256k1_context* ctx;
        secp256k1_scratch_space* scratch;
} secp256k1_scratch_space_wrapper;

// php_secp256k1_nonce_function_data embeds state required for secp256k1_ecdsa_sign to
// call a userland PHP function, as well as containing an (optional) zval* to be
// unpacked and used as arbitrary data to the custom nonce function
typedef struct php_secp256k1_nonce_function_data {
    zend_fcall_info* fci;
    zend_fcall_info_cache* fcc;
    zval* data;
} php_secp256k1_nonce_function_data;

// php_secp256k1_nonce_function_callback is an implementation of secp256k1_nonce_function
// designed to call a PHP land function to calculate a nonce for the signature algorithm.
// it expects that the arbitrary *data is *php_secp256k1_nonce_function_data, so it has
// sufficient context to call the embedded PHP function, and pass optional additional data
// if present. it writes the nonce provided the PHP function to *nonce32 for the signing
// algorithm to continue.
static int php_secp256k1_nonce_function_callback(unsigned char *nonce32, const unsigned char *msg32,
                               const unsigned char *key32, const unsigned char *algo16,
                               void *data, unsigned int attempt) {
    php_secp256k1_nonce_function_data* callback;
    zend_string* output_str;
    zval retval, zvalout;
    zval args[6];
    int result, i;

    callback = (php_secp256k1_nonce_function_data*) data;
    callback->fci->size = sizeof(*(callback->fci));
    callback->fci->object = NULL;
    callback->fci->retval = &retval;
    callback->fci->params = args;
    callback->fci->param_count = 6;
    ZVAL_NEW_STR(&zvalout, zend_string_init("", 0, 0));

    // wrt ownership, args 0-3 & 5 are managed by us in order to
    // receive the result, and pass in the x & y parameters.
    // arg 3 is owned by the caller of secp256k1_ecdh.
    ZVAL_NEW_REF(&args[0], &zvalout);
    ZVAL_STR(&args[1], zend_string_init((const char *) msg32, 32, 0));
    ZVAL_STR(&args[2], zend_string_init((const char *) key32, 32, 0));
    if (algo16 == NULL) {
        ZVAL_NULL(&args[3]);
    } else {
        // This is impossible to test unless secp256k1 starts to use
        // this value, which for ECDSA & schnorr are presently null.
        ZVAL_STR(&args[3], zend_string_init((const char *) algo16, strlen((const char *) algo16), 0));
    }
    if (callback->data != NULL) {
        zval* data = callback->data;
        args[4] = *data;
    } else {
        ZVAL_NULL(&args[4]);
    }
    ZVAL_LONG(&args[5], (zend_long) attempt);

    result = zend_call_function(callback->fci, callback->fcc) == SUCCESS;

    // check function invocation result
    if (result) {
        // now respect return value
        if (Z_TYPE(retval) == IS_FALSE) {
            result = 0;
        } else if (Z_TYPE(retval) == IS_TRUE) {
            result = 1;
        } else if (Z_TYPE(retval) == IS_LONG) {
            result = Z_LVAL(retval);
        }
    }

    // there's more! what if the length doesn't match? avoid.
    if (result) {
        output_str = Z_STR_P(Z_REFVAL(args[0]));
        if (output_str->len != 32) {
            // this perhaps ought to be an exception,
            // as these callbacks _MUST_ write 32 bytes
            result = 0;
        }
    }

    // callback OK & length correct
    if (result) {
        memcpy(nonce32, output_str->val, 32);
    }

    // zval_dtor on our args. arg 3 is managed elsewhere.
    zval_dtor(&args[0]);
    zval_dtor(&args[1]);
    zval_dtor(&args[2]);
    zval_dtor(&args[3]);
    zval_dtor(&args[5]);

    return result;
}

/* Function argument documentation */

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_ecdsa_signature_parse_der_lax, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_ecdsa_signature_parse_der_lax, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, sigLaxDerIn, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_create, IS_RESOURCE, NULL, 1)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_create, IS_RESOURCE, 1)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_clone, IS_RESOURCE, NULL, 1)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_clone, IS_RESOURCE, 1)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_destroy, _IS_BOOL, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_destroy, _IS_BOOL, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_parse, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_parse, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, publicKeyIn, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_serialize, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_serialize, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, publicKeyOut, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, ecPublicKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_parse_compact, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_parse_compact, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, sig64In, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_parse_der, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_parse_der, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, sigDerIn, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_serialize_der, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_serialize_der, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, sigDerOut, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaSignature, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_serialize_compact, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_serialize_compact, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, sig64Out, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaSignature, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_verify, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_verify, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, ecdsaSignature, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, ecPublicKey, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_normalize, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_signature_normalize, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureNormalized, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaSignature, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_sign, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_sign, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
    ZEND_ARG_CALLABLE_INFO(0, noncefp, 1)
    ZEND_ARG_INFO(0, ndata)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_seckey_verify, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_seckey_verify, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_create, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_create, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_negate, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_negate, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, secKey, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_negate, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_negate, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_tweak_add, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_tweak_add, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, seckey, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_tweak_add, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_tweak_add, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_tweak_mul, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_privkey_tweak_mul, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, seckey, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_tweak_mul, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_tweak_mul, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_randomize, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_context_randomize, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, seed32, IS_STRING, 1)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_combine, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ec_pubkey_combine, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, combinedEcPublicKey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, publicKeys, IS_ARRAY, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_default, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_default, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(1, data, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algo16, IS_STRING, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_TYPE_INFO(0, attempt, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_rfc6979, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_rfc6979, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(1, nonce32, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algo16, IS_STRING, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_TYPE_INFO(0, attempt, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_scratch_space_create, IS_RESOURCE, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_scratch_space_create, IS_RESOURCE, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, size, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_scratch_space_destroy, IS_RESOURCE, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_scratch_space_destroy, IS_RESOURCE, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, scratch, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_create, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_create, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, pubkey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, seckey, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_parse, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_parse, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, pubkey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, input32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_serialize, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_serialize, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, output32, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, pubkey, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_from_pubkey, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_from_pubkey, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, xonly_pubkey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(1, sign, IS_LONG, 1)
    ZEND_ARG_TYPE_INFO(0, pubkey, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_privkey_tweak_add, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_privkey_tweak_add, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, seckey, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_tweak_add, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_tweak_add, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, outputPubKey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(1, isPositive, IS_LONG, 1)
    ZEND_ARG_TYPE_INFO(0, internalPubKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_tweak_verify, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_xonly_pubkey_tweak_verify, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, outputPubKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, isPositive, IS_LONG, 0)
    ZEND_ARG_TYPE_INFO(0, internalPubKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, tweak32, IS_STRING, 0)
ZEND_END_ARG_INFO();

//recovery
#ifdef SECP256K1_MODULE_RECOVERY
#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_parse_compact, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_parse_compact, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaRecoverableSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, sig64, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, recId, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_convert, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_convert, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignature, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaRecoverableSignature, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_serialize_compact, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recoverable_signature_serialize_compact, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, sig64Out, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(1, recIdOut, IS_LONG, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaRecoverableSignature, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_sign_recoverable, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_sign_recoverable, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaRecoverableSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recover, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdsa_recover, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecPublicKey, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, ecdsaRecoverableSignature, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
ZEND_END_ARG_INFO();
#endif

//ecdh
#ifdef SECP256K1_MODULE_ECDH
#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdh, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_ecdh, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, result, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, ecPublicKey, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, privKey, IS_STRING, 0)
    ZEND_ARG_CALLABLE_INFO(0, hashfxn, 1)
    ZEND_ARG_TYPE_INFO(0, outputLen, IS_LONG, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO();
#endif

//schnorrsig
#ifdef SECP256K1_MODULE_SCHNORRSIG

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_serialize, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_serialize, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, sigout, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, schnorrsig, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_parse, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_parse, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, sigout, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, sigin, IS_STRING, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_sign, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_sign, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(1, ecdsaSignatureOut, IS_RESOURCE, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
    ZEND_ARG_CALLABLE_INFO(0, noncefp, 1)
    ZEND_ARG_INFO(0, ndata)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_verify, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_verify, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, schnorrsig, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, pubkey, IS_RESOURCE, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_verify_batch, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_schnorrsig_verify_batch, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(0, context, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, scratch, IS_RESOURCE, 0)
    ZEND_ARG_TYPE_INFO(0, pubkeys, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, msg32s, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, sigs, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO(0, numsigs, IS_LONG, 0)
ZEND_END_ARG_INFO();

#if (PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70200)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_bipschnorr, IS_LONG, NULL, 0)
#else
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_nonce_function_bipschnorr, IS_LONG, 0)
#endif
    ZEND_ARG_TYPE_INFO(1, nonce32, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, msg32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, key32, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, algo16, IS_STRING, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_TYPE_INFO(0, attempt, IS_LONG, 0)
ZEND_END_ARG_INFO();

#endif
/* {{{ resource_functions[]
 *
 * Every user visible function must have an entry in resource_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
        // Not part of secp256k1 api, but taken from their contrib code section
        PHP_FE(ecdsa_signature_parse_der_lax,                arginfo_ecdsa_signature_parse_der_lax)

        // secp256k1.h
        PHP_FE(secp256k1_context_create,                     arginfo_secp256k1_context_create)
        PHP_FE(secp256k1_context_clone,                      arginfo_secp256k1_context_clone)
        PHP_FE(secp256k1_context_destroy,                    arginfo_secp256k1_context_destroy)

        PHP_FE(secp256k1_ec_pubkey_parse,                    arginfo_secp256k1_ec_pubkey_parse)
        PHP_FE(secp256k1_ec_pubkey_serialize,                arginfo_secp256k1_ec_pubkey_serialize)

        PHP_FE(secp256k1_ecdsa_signature_parse_compact,      arginfo_secp256k1_ecdsa_signature_parse_compact)
        PHP_FE(secp256k1_ecdsa_signature_parse_der,          arginfo_secp256k1_ecdsa_signature_parse_der)
        PHP_FE(secp256k1_ecdsa_signature_serialize_der,      arginfo_secp256k1_ecdsa_signature_serialize_der)
        PHP_FE(secp256k1_ecdsa_signature_serialize_compact,  arginfo_secp256k1_ecdsa_signature_serialize_compact)

        PHP_FE(secp256k1_ecdsa_verify,                       arginfo_secp256k1_ecdsa_verify)
        PHP_FE(secp256k1_ecdsa_signature_normalize,          arginfo_secp256k1_ecdsa_signature_normalize)
        PHP_FE(secp256k1_ecdsa_sign,                         arginfo_secp256k1_ecdsa_sign)
        PHP_FE(secp256k1_ec_seckey_verify,                   arginfo_secp256k1_ec_seckey_verify)

        PHP_FE(secp256k1_ec_pubkey_create,                   arginfo_secp256k1_ec_pubkey_create)
        PHP_FE(secp256k1_ec_privkey_negate,                  arginfo_secp256k1_ec_privkey_negate)
        PHP_FE(secp256k1_ec_pubkey_negate,                   arginfo_secp256k1_ec_pubkey_negate)

        PHP_FE(secp256k1_ec_privkey_tweak_add,               arginfo_secp256k1_ec_privkey_tweak_add)
        PHP_FE(secp256k1_ec_pubkey_tweak_add,                arginfo_secp256k1_ec_pubkey_tweak_add)
        PHP_FE(secp256k1_ec_privkey_tweak_mul,               arginfo_secp256k1_ec_privkey_tweak_mul)
        PHP_FE(secp256k1_ec_pubkey_tweak_mul,                arginfo_secp256k1_ec_pubkey_tweak_mul)

        PHP_FE(secp256k1_context_randomize,                  arginfo_secp256k1_context_randomize)
        PHP_FE(secp256k1_ec_pubkey_combine,                  arginfo_secp256k1_ec_pubkey_combine)

        PHP_FE(secp256k1_scratch_space_create,               arginfo_secp256k1_scratch_space_create)
        PHP_FE(secp256k1_scratch_space_destroy,              arginfo_secp256k1_scratch_space_destroy)

        PHP_FE(secp256k1_nonce_function_default,             arginfo_secp256k1_nonce_function_default)
        PHP_FE(secp256k1_nonce_function_rfc6979,             arginfo_secp256k1_nonce_function_rfc6979)

        PHP_FE(secp256k1_xonly_pubkey_create,                arginfo_secp256k1_xonly_pubkey_create)
        PHP_FE(secp256k1_xonly_pubkey_parse,                 arginfo_secp256k1_xonly_pubkey_parse)
        PHP_FE(secp256k1_xonly_pubkey_serialize,             arginfo_secp256k1_xonly_pubkey_serialize)
        PHP_FE(secp256k1_xonly_pubkey_from_pubkey,           arginfo_secp256k1_xonly_pubkey_from_pubkey)
        PHP_FE(secp256k1_xonly_privkey_tweak_add,            arginfo_secp256k1_xonly_privkey_tweak_add)
        PHP_FE(secp256k1_xonly_pubkey_tweak_add,             arginfo_secp256k1_xonly_pubkey_tweak_add)
        PHP_FE(secp256k1_xonly_pubkey_tweak_verify,          arginfo_secp256k1_xonly_pubkey_tweak_verify)
        // secp256k1_recovery.h
#ifdef SECP256K1_MODULE_RECOVERY
        PHP_FE(secp256k1_ecdsa_recoverable_signature_parse_compact, arginfo_secp256k1_ecdsa_recoverable_signature_parse_compact)
        PHP_FE(secp256k1_ecdsa_recoverable_signature_convert, arginfo_secp256k1_ecdsa_recoverable_signature_convert)
        PHP_FE(secp256k1_ecdsa_recoverable_signature_serialize_compact, arginfo_secp256k1_ecdsa_recoverable_signature_serialize_compact)
        PHP_FE(secp256k1_ecdsa_sign_recoverable,             arginfo_secp256k1_ecdsa_sign_recoverable)
        PHP_FE(secp256k1_ecdsa_recover,                      arginfo_secp256k1_ecdsa_recover)
#endif

        // secp256k1_ecdh.h
#ifdef SECP256K1_MODULE_ECDH
        PHP_FE(secp256k1_ecdh,                               arginfo_secp256k1_ecdh)
#endif

        // secp256k1_schnorr.h
#ifdef SECP256K1_MODULE_SCHNORRSIG
        PHP_FE(secp256k1_schnorrsig_serialize,               arginfo_secp256k1_schnorrsig_serialize)
        PHP_FE(secp256k1_schnorrsig_parse,                   arginfo_secp256k1_schnorrsig_parse)
        PHP_FE(secp256k1_schnorrsig_sign,                    arginfo_secp256k1_schnorrsig_sign)
        PHP_FE(secp256k1_schnorrsig_verify,                  arginfo_secp256k1_schnorrsig_verify)
        PHP_FE(secp256k1_schnorrsig_verify_batch,            arginfo_secp256k1_schnorrsig_verify_batch)
        PHP_FE(secp256k1_nonce_function_bipschnorr,          arginfo_secp256k1_nonce_function_bipschnorr)
#endif

        PHP_FE_END	/* Must be the last line in resource_functions[] */
};
/* }}} */

/* resource numbers */
static int le_secp256k1_ctx;
static int le_secp256k1_pubkey;
static int le_secp256k1_sig;
static int le_secp256k1_scratch_space;
static int le_secp256k1_schnorrsig;
static int le_secp256k1_xonly_pubkey;
static int le_secp256k1_recoverable_sig;

/* dtor functions */
static void secp256k1_ctx_dtor(zend_resource *rsrc TSRMLS_DC)
{
    secp256k1_context *ctx = (secp256k1_context*) rsrc->ptr;
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

static void secp256k1_pubkey_dtor(zend_resource *rsrc TSRMLS_DC)
{
    secp256k1_pubkey *pubkey = (secp256k1_pubkey*) rsrc->ptr;
    if (pubkey) {
        efree(pubkey);
    }
}

static void secp256k1_sig_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_ecdsa_signature *sig = (secp256k1_ecdsa_signature*) rsrc->ptr;
    if (sig) {
        efree(sig);
    }
}

static void secp256k1_scratch_space_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_scratch_space_wrapper *scratch_wrap = (secp256k1_scratch_space_wrapper *) rsrc->ptr;
    if (scratch_wrap) {
        secp256k1_scratch_space_destroy(scratch_wrap->ctx, scratch_wrap->scratch);
        efree(scratch_wrap);
    }
}

static void secp256k1_xonly_pubkey_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_xonly_pubkey *key = (secp256k1_xonly_pubkey *) rsrc->ptr;
    if (key) {
        efree(key);
    }
}

#ifdef SECP256K1_MODULE_RECOVERY
static void secp256k1_recoverable_sig_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_ecdsa_recoverable_signature *sig = (secp256k1_ecdsa_recoverable_signature*) rsrc->ptr;
    if (sig) {
        efree(sig);
    }
}
#endif

#ifdef SECP256K1_MODULE_SCHNORRSIG
static void secp256k1_schnorrsig_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_schnorrsig *sig = (secp256k1_schnorrsig *) rsrc->ptr;
    if (sig) {
        efree(sig);
    }
}
#endif

// helper functions to extract pointers from resource zvals

// attempt to read a sec256k1_context* from the provided resource zval
static secp256k1_context* php_get_secp256k1_context(zval* pcontext) {
    return (secp256k1_context *)zend_fetch_resource2_ex(pcontext, SECP256K1_CTX_RES_NAME, le_secp256k1_ctx, -1);
}

// attempt to read a sec256k1_ecdsa_signature* from the provided resource zval
static secp256k1_ecdsa_signature* php_get_secp256k1_ecdsa_signature(zval *psig) {
    return (secp256k1_ecdsa_signature *)zend_fetch_resource2_ex(psig, SECP256K1_SIG_RES_NAME, le_secp256k1_sig, -1);
}

// attempt to read a sec256k1_pubkey* from the provided resource zval
static secp256k1_pubkey* php_get_secp256k1_pubkey(zval *pkey) {
    return (secp256k1_pubkey *)zend_fetch_resource2_ex(pkey, SECP256K1_PUBKEY_RES_NAME, le_secp256k1_pubkey, -1);
}

// attempt to read a sec256k1_scratch_space * from the provided resource zval
static secp256k1_scratch_space_wrapper * php_get_secp256k1_scratch_space(zval *psig) {
    return (secp256k1_scratch_space_wrapper *)zend_fetch_resource2_ex(psig, SECP256K1_SCRATCH_SPACE_RES_NAME, le_secp256k1_scratch_space, -1);
}
// attempt to read a sec256k1_xonly_pubkey* from the provided resource zval
static secp256k1_xonly_pubkey* php_get_secp256k1_xonly_pubkey(zval *key) {
    return (secp256k1_xonly_pubkey *)zend_fetch_resource2_ex(key, SECP256K1_XONLY_PUBKEY_RES_NAME, le_secp256k1_xonly_pubkey, -1);
}
#ifdef SECP256K1_MODULE_RECOVERY
// attempt to read a sec256k1_ecdsa_recoverable_signature* from the provided resource zval
static secp256k1_ecdsa_recoverable_signature* php_get_secp256k1_ecdsa_recoverable_signature(zval *precsig) {
    return (secp256k1_ecdsa_recoverable_signature *)zend_fetch_resource2_ex(precsig, SECP256K1_RECOVERABLE_SIG_RES_NAME, le_secp256k1_recoverable_sig, -1);
}
#endif

#ifdef SECP256K1_MODULE_SCHNORRSIG
// attempt to read a sec256k1_schnorrsig* from the provided resource zval
static secp256k1_schnorrsig* php_get_secp256k1_schnorr_signature(zval *psig) {
    return (secp256k1_schnorrsig *)zend_fetch_resource2_ex(psig, SECP256K1_SCHNORRSIG_RES_NAME, le_secp256k1_schnorrsig, -1);
}

#endif

PHP_MINIT_FUNCTION(secp256k1) {
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_CONTEXT", SECP256K1_CTX_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_PUBKEY", SECP256K1_PUBKEY_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_SIG", SECP256K1_SIG_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_SCRATCH_SPACE", SECP256K1_SCRATCH_SPACE_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_XONLY_PUBKEY", SECP256K1_XONLY_PUBKEY_RES_NAME, CONST_CS | CONST_PERSISTENT);

    /** Flags to pass to secp256k1_context_create */
    REGISTER_LONG_CONSTANT("SECP256K1_CONTEXT_VERIFY", SECP256K1_CONTEXT_VERIFY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_CONTEXT_SIGN", SECP256K1_CONTEXT_SIGN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_CONTEXT_NONE", SECP256K1_CONTEXT_NONE, CONST_CS | CONST_PERSISTENT);

    /** Flags to pass to secp256k1_ec_pubkey_serialize */
    REGISTER_LONG_CONSTANT("SECP256K1_EC_COMPRESSED", SECP256K1_EC_COMPRESSED, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_EC_UNCOMPRESSED", SECP256K1_EC_UNCOMPRESSED, CONST_CS | CONST_PERSISTENT);

    /** Prefix byte used to tag various encoded curvepoints for specific purposes */
    REGISTER_LONG_CONSTANT("SECP256K1_TAG_PUBKEY_EVEN", SECP256K1_TAG_PUBKEY_EVEN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_TAG_PUBKEY_ODD", SECP256K1_TAG_PUBKEY_ODD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_TAG_PUBKEY_UNCOMPRESSED", SECP256K1_TAG_PUBKEY_UNCOMPRESSED, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_TAG_PUBKEY_HYBRID_EVEN", SECP256K1_TAG_PUBKEY_HYBRID_EVEN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_TAG_PUBKEY_HYBRID_ODD", SECP256K1_TAG_PUBKEY_HYBRID_ODD, CONST_CS | CONST_PERSISTENT);
    le_secp256k1_ctx = zend_register_list_destructors_ex(secp256k1_ctx_dtor, NULL, SECP256K1_CTX_RES_NAME, module_number);
    le_secp256k1_pubkey = zend_register_list_destructors_ex(secp256k1_pubkey_dtor, NULL, SECP256K1_PUBKEY_RES_NAME, module_number);
    le_secp256k1_sig = zend_register_list_destructors_ex(secp256k1_sig_dtor, NULL, SECP256K1_SIG_RES_NAME, module_number);
    le_secp256k1_scratch_space = zend_register_list_destructors_ex(secp256k1_scratch_space_dtor, NULL, SECP256K1_SCRATCH_SPACE_RES_NAME, module_number);
    le_secp256k1_xonly_pubkey = zend_register_list_destructors_ex(secp256k1_xonly_pubkey_dtor, NULL, SECP256K1_XONLY_PUBKEY_RES_NAME, module_number);

#ifdef SECP256K1_MODULE_RECOVERY
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_RECOVERABLE_SIG", SECP256K1_RECOVERABLE_SIG_RES_NAME, CONST_CS | CONST_PERSISTENT);
    le_secp256k1_recoverable_sig = zend_register_list_destructors_ex(secp256k1_recoverable_sig_dtor, NULL, SECP256K1_RECOVERABLE_SIG_RES_NAME, module_number);
#endif

#ifdef SECP256K1_MODULE_SCHNORRSIG
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_SCHNORRSIG", SECP256K1_SCHNORRSIG_RES_NAME, CONST_CS | CONST_PERSISTENT);
    le_secp256k1_schnorrsig = zend_register_list_destructors_ex(secp256k1_schnorrsig_dtor, NULL, SECP256K1_SCHNORRSIG_RES_NAME, module_number);
#endif

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1) {
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
ZEND_GET_MODULE(secp256k1)
#endif

/* {{{ proto ?resource secp256k1_context_create(int flags)
 * Create a secp256k1 context object. */
PHP_FUNCTION(secp256k1_context_create)
{
    long flags;
    secp256k1_context * ctx;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &flags) == FAILURE) {
        return;
    }

    if ((flags & ~(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) > 0) {
        return;
    }

    ctx = secp256k1_context_create(flags);
    RETURN_RES(zend_register_resource(ctx, le_secp256k1_ctx));
}
/* }}} */

/* {{{ proto bool secp256k1_context_destroy(resource context)
 * Destroy a secp256k1 context object. */
PHP_FUNCTION(secp256k1_context_destroy)
{
    zval *zCtx;
    secp256k1_context *ctx;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zCtx) == FAILURE) {
        RETURN_FALSE;
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_FALSE;
    }

    zend_list_close(Z_RES_P(zCtx));
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto ?resource secp256k1_context_clone(resource context)
 * Copies a secp256k1 context object. */
PHP_FUNCTION(secp256k1_context_clone)
{
    zval *zCtx;
    secp256k1_context *ctx;
    secp256k1_context *newCtx;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zCtx) == FAILURE) {
        RETURN_NULL();
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_NULL();
    }

    newCtx = secp256k1_context_clone(ctx);
    RETURN_RES(zend_register_resource(newCtx, le_secp256k1_ctx));
}
/* }}} */

/* {{{ proto int secp256k1_context_randomize(resource context, [string bytes32 = NULL])
 * Updates the context randomization. */
PHP_FUNCTION(secp256k1_context_randomize)
{
    zval *zCtx, *zSeed = NULL;
    secp256k1_context *ctx;
    unsigned char *seed32 = NULL;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|z", &zCtx, &zSeed) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (zSeed != NULL) {
        if (Z_TYPE_P(zSeed) == IS_STRING) {
            if (Z_STRLEN_P(zSeed) != 32) {
                zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC,
                        "secp256k1_context_randomize(): Parameter 2 should be 32 bytes");
                return;
            }
            seed32 = (unsigned char *) Z_STRVAL_P(zSeed);
        }
    }

    result = secp256k1_context_randomize(ctx, seed32);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_signature_parse_der(resource ctx, resource &sig, string sigIn)
 * Parse a DER ECDSA signature. */
PHP_FUNCTION(secp256k1_ecdsa_signature_parse_der)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    zend_string *sigin;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSig, &sigin) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    sig = (secp256k1_ecdsa_signature *) emalloc(sizeof(secp256k1_ecdsa_signature));
    result = secp256k1_ecdsa_signature_parse_der(ctx, sig, (unsigned char *) sigin->val, sigin->len);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(sig, le_secp256k1_sig));
    } else {
        // only free when operation fails, won't return this resource
        efree(sig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_signature_serialize_der(resource context, string &sigOut, resource sig)
 * Serialize an ECDSA signature in DER format. */
PHP_FUNCTION(secp256k1_ecdsa_signature_serialize_der)
{
    zval *zCtx, *zSig, *zSigOut;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    size_t sigoutlen = MAX_SIGNATURE_LENGTH;
    unsigned char sigout[MAX_SIGNATURE_LENGTH];
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zSigOut, &zSig) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((sig = php_get_secp256k1_ecdsa_signature(zSig)) == NULL) {
        RETURN_LONG(result);
    }

    result = secp256k1_ecdsa_signature_serialize_der(ctx, sigout, &sigoutlen, sig);
    if (result) {
        zval_dtor(zSigOut);
        ZVAL_STRINGL(zSigOut, (char *)&sigout, sigoutlen);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_signature_parse_compact(resource context, resource &sig, string sig64, int recid)
 * Parse an ECDSA signature in compact (64 bytes) format. */
PHP_FUNCTION(secp256k1_ecdsa_signature_parse_compact)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    zend_string *input64;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSig, &input64) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (input64->len != COMPACT_SIGNATURE_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ecdsa_signature_parse_compact(): Parameter 3 should be 64 bytes");
        return;
    }

    sig = emalloc(sizeof(secp256k1_ecdsa_signature));
    result = secp256k1_ecdsa_signature_parse_compact(ctx, sig, (unsigned char *) input64->val);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(sig, le_secp256k1_sig));
    } else {
        // only free when operation fails, won't return this resource
        efree(sig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_signature_serialize_compact(resource context, string &sigOut, resource sig)
 * Serialize an ECDSA signature in compact (64 byte) format. */
PHP_FUNCTION(secp256k1_ecdsa_signature_serialize_compact)
{
    zval *zCtx, *zSig, *zSigOut;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    unsigned char sigOut[COMPACT_SIGNATURE_LENGTH];
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zSigOut, &zSig) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((sig = php_get_secp256k1_ecdsa_signature(zSig)) == NULL) {
        RETURN_LONG(result);
    }

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, sigOut, sig);

    zval_dtor(zSigOut);
    ZVAL_STRINGL(zSigOut, (char *) &sigOut, COMPACT_SIGNATURE_LENGTH);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int ecdsa_signature_parse_der_lax(resource context, resource &sigOut, string sigIn)
 * Parse a signature in "lax DER" format. */
PHP_FUNCTION(ecdsa_signature_parse_der_lax)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    zend_string *sigin;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSig, &sigin) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    sig = (secp256k1_ecdsa_signature *) emalloc(sizeof(secp256k1_ecdsa_signature));
    result = ecdsa_signature_parse_der_lax(ctx, sig, (unsigned char *) sigin->val, sigin->len);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(sig, le_secp256k1_sig));
    } else {
        // only free when operation fails, won't return this resource
        efree(sig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_signature_normalize(resource context, resource &sigNormal, resource sig)
 * Convert a signature to a normalized lower-S form. */
PHP_FUNCTION(secp256k1_ecdsa_signature_normalize)
{
    zval *zCtx, *zSigIn, *zSigOut;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sigout, *sigin;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zSigOut, &zSigIn) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((sigin = php_get_secp256k1_ecdsa_signature(zSigIn)) == NULL) {
        RETURN_LONG(result);
    }

    sigout = (secp256k1_ecdsa_signature *) emalloc(sizeof(secp256k1_ecdsa_signature));
    result = secp256k1_ecdsa_signature_normalize(ctx, sigout, sigin);

    zval_dtor(zSigOut);
    ZVAL_RES(zSigOut, zend_register_resource(sigout, le_secp256k1_sig));
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_verify(resource context, resource sig, string msg32, resource pubKey)
 * Verify an ECDSA signature. */
PHP_FUNCTION(secp256k1_ecdsa_verify) {
    zval *zCtx, *zSig, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *sig;
    secp256k1_pubkey *pubkey;
    zend_string *msg32;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrSr", &zCtx, &zSig, &msg32, &zPubKey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((sig = php_get_secp256k1_ecdsa_signature(zSig)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    result = secp256k1_ecdsa_verify(ctx, sig, (unsigned char *) msg32->val, pubkey);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_sign(resource context, resource &sig, string msg32, string key32)
 * Create an ECDSA signature. */
PHP_FUNCTION (secp256k1_ecdsa_sign)
{
    zval *zCtx, *zSig, *zData = NULL;
    zend_string *msg32, *seckey;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *newsig;
    secp256k1_nonce_function noncefp = NULL;
    void *ndata = NULL;
    zend_fcall_info fci = empty_fcall_info;
    zend_fcall_info_cache fcc = empty_fcall_info_cache;
    php_secp256k1_nonce_function_data calldata;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/SS|fz",
        &zCtx, &zSig, &msg32, &seckey, &fci, &fcc, &zData) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (msg32->len != HASH_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0
        TSRMLS_CC, "secp256k1_ecdsa_sign(): Parameter 3 should be 32 bytes");
        return;
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0
        TSRMLS_CC, "secp256k1_ecdsa_sign(): Parameter 4 should be 32 bytes");
        return;
    }

    if (ZEND_NUM_ARGS() > 4) {
        noncefp = php_secp256k1_nonce_function_callback;
        calldata.fci = &fci;
        calldata.fcc = &fcc;
        if (zData == NULL) {
            calldata.data = NULL;
        } else {
            calldata.data = zData;
        }
        ndata = (void *) &calldata;
    }

    newsig = (secp256k1_ecdsa_signature *) emalloc(sizeof(secp256k1_ecdsa_signature));
    result = secp256k1_ecdsa_sign(ctx, newsig, (unsigned char *) msg32->val, (unsigned char *) seckey->val, noncefp, ndata);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(newsig, le_secp256k1_sig));
    } else {
        // only free when operation fails, won't return this resource
        efree(newsig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_seckey_verify(resource context, string key32)
 * Verify an ECDSA secret key. */
PHP_FUNCTION(secp256k1_ec_seckey_verify)
{
    zval *zCtx;
    secp256k1_context *ctx;
    zend_string *seckey;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rS", &zCtx, &seckey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_seckey_verify(): Parameter 1 should be 32 bytes");
        return;
    }

    result = secp256k1_ec_seckey_verify(ctx, (unsigned char *) seckey->val);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_create(resource context, resource &pubKey, string key32)
 * Compute the public key for a secret key. */
PHP_FUNCTION(secp256k1_ec_pubkey_create)
{
    zval *zCtx;
    zval *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    zend_string *seckey;
    zend_resource *pubKeyResource;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zPubKey, &seckey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_pubkey_create(): Parameter 2 should be 32 bytes");
        return;
    }

    pubkey = (secp256k1_pubkey *) emalloc(sizeof(secp256k1_pubkey));
    result = secp256k1_ec_pubkey_create(ctx, pubkey, (unsigned char *)seckey->val);
    if (result) {
        zval_dtor(zPubKey);
        ZVAL_RES(zPubKey, zend_register_resource(pubkey, le_secp256k1_pubkey));
    } else {
        // only free when operation fails, won't return this resource
        efree(pubkey);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_privkey_negate(resource context, string key32)
 * Negates a private key in place. */
PHP_FUNCTION(secp256k1_ec_privkey_negate)
{
    zval *zCtx, *zPrivKey;
    secp256k1_context *ctx;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/", &zCtx, &zPrivKey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (Z_STRLEN_P(zPrivKey) != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_privkey_negate(): Parameter 2 should be 32 bytes");
        return;
    }

    unsigned char newseckey[SECRETKEY_LENGTH];
    memcpy(newseckey, Z_STRVAL_P(zPrivKey), SECRETKEY_LENGTH);
    result = secp256k1_ec_privkey_negate(ctx, newseckey);

    zval_dtor(zPrivKey);
    ZVAL_STRINGL(zPrivKey, (char *)&newseckey, SECRETKEY_LENGTH);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_negate(resource ctx, resource pubkey)
 * Negates a public key in place. */
PHP_FUNCTION(secp256k1_ec_pubkey_negate)
{
    zval *zCtx, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rr", &zCtx, &zPubKey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    result = secp256k1_ec_pubkey_negate(ctx, pubkey);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_parse(resource secp256k1_context, resource &pubKey, string pubKeyIn)
 * Parse a variable-length public key into the pubkey object. */
PHP_FUNCTION(secp256k1_ec_pubkey_parse)
{
    zval *zCtx, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    zend_string *pubkeyin;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zPubKey, &pubkeyin) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    pubkey = (secp256k1_pubkey *) emalloc(sizeof(secp256k1_pubkey));
    result = secp256k1_ec_pubkey_parse(ctx, pubkey, (unsigned char *)pubkeyin->val, pubkeyin->len);
    if (result) {
        zval_dtor(zPubKey);
        ZVAL_RES(zPubKey, zend_register_resource(pubkey, le_secp256k1_pubkey));
    } else {
        // only free when operation fails, won't return this resource
        efree(pubkey);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_serialize(resource context, string &pubKeyOut, resource pubKey, long flags)
 * Serialize a pubkey object into a serialized byte sequence. */
PHP_FUNCTION(secp256k1_ec_pubkey_serialize)
{
    zval *zCtx, *zPubKey, *zPubOut;
    secp256k1_context *ctx;
    secp256k1_pubkey * pubkey;
    int result = 0;
    size_t pubkeylen;
    zend_long flags;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rl", &zCtx, &zPubOut, &zPubKey, &flags) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    pubkeylen = (flags == SECP256K1_EC_COMPRESSED) ? PUBKEY_COMPRESSED_LENGTH : PUBKEY_UNCOMPRESSED_LENGTH;

    unsigned char pubkeyout[PUBKEY_UNCOMPRESSED_LENGTH];
    result = secp256k1_ec_pubkey_serialize(ctx, pubkeyout, &pubkeylen, pubkey, flags);

    zval_dtor(zPubOut);
    ZVAL_STRINGL(zPubOut, (char *)&pubkeyout, pubkeylen);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_privkey_tweak_add(resource context, string &key32, string tweak32)
 * Tweak a private key by adding tweak to it. */
PHP_FUNCTION(secp256k1_ec_privkey_tweak_add)
{
    zval *zCtx, *zSecKey;
    secp256k1_context *ctx;
    zend_string *zTweak;
    unsigned char *tweak;
    unsigned char newseckey[SECRETKEY_LENGTH];
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSecKey, &zTweak) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (Z_STRLEN_P(zSecKey) != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_privkey_tweak_add(): Parameter 2 should be 32 bytes");
        return;
    }

    if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_privkey_tweak_add(): Parameter 3 should be 32 bytes");
        return;
    }

    memcpy(newseckey, Z_STRVAL_P(zSecKey), SECRETKEY_LENGTH);
    result = secp256k1_ec_privkey_tweak_add(ctx, newseckey, (unsigned char *) zTweak->val);

    zval_dtor(zSecKey);
    ZVAL_STRINGL(zSecKey, (const char *) newseckey, SECRETKEY_LENGTH);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_tweak_add(resource context, resource pubKey, string tweak32)
 * Tweak a public key by adding tweak times the generator to it. */
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_add)
{
    zval *zCtx, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    zend_string *zTweak;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrS", &zCtx, &zPubKey, &zTweak) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_pubkey_tweak_add(): Parameter 3 should be 32 bytes");
        return;
    }

    result = secp256k1_ec_pubkey_tweak_add(ctx, pubkey, (unsigned char *)zTweak->val);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_privkey_tweak_mul(resource context, string &key32, string tweak32)
 * Tweak a private key by multiplying it by a tweak. */
PHP_FUNCTION(secp256k1_ec_privkey_tweak_mul)
{
    zval *zCtx, *zSecKey;
    unsigned char newseckey[SECRETKEY_LENGTH];
    zend_string *zTweak;
    secp256k1_context *ctx;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSecKey, &zTweak) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (Z_STRLEN_P(zSecKey) != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_privkey_tweak_mul(): Parameter 2 should be 32 bytes");
        return;
    }

    if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_privkey_tweak_mul(): Parameter 3 should be 32 bytes");
        return;
    }

    memcpy(newseckey, Z_STRVAL_P(zSecKey), SECRETKEY_LENGTH);
    result = secp256k1_ec_privkey_tweak_mul(ctx, newseckey, (unsigned char *) zTweak->val);

    zval_dtor(zSecKey);
    ZVAL_STRINGL(zSecKey, (const char *) newseckey, SECRETKEY_LENGTH);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_tweak_mul(resource context, resource pubKey, string tweak32)
 * Tweak a public key by multiplying it by a tweak value. */
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_mul)
{
    zval *zCtx, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    unsigned char *newpubkey;
    size_t newpubkeylen;
    zend_string *zTweak;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrS", &zCtx, &zPubKey, &zTweak) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ec_pubkey_tweak_mul(): Parameter 3 should be 32 bytes");
        return;
    }

    result = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, (unsigned char *) zTweak->val);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ec_pubkey_combine(resource context, resource &pubKey, resource[] vPubKey)
 * Add a number of public keys together. */
PHP_FUNCTION(secp256k1_ec_pubkey_combine)
{
    zval *arr, *zCtx, *zPubkeyCombined, *arrayZval;
    secp256k1_context *ctx;
    secp256k1_pubkey *ptr, *combined;
    zend_string *arrayKeyStr;
    HashTable *arr_hash;
    HashPosition pointer;
    const secp256k1_pubkey ** pubkeys;
    int result = 0, i = 0;
    size_t array_count;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/a", &zCtx, &zPubkeyCombined, &arr) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    arr_hash = Z_ARRVAL_P(arr);
    array_count = (size_t) zend_hash_num_elements(arr_hash);
    // emalloc terminates the request if memory can't be allocated.
    pubkeys = emalloc(sizeof(secp256k1_pubkey *) * array_count);

    ZEND_HASH_FOREACH_KEY_VAL(arr_hash, i, arrayKeyStr, arrayZval) {
        if ((ptr = php_get_secp256k1_pubkey(arrayZval)) == NULL) {
            efree(pubkeys);
            RETURN_LONG(result);
        }

        pubkeys[i++] = ptr;
    } ZEND_HASH_FOREACH_END();

    combined = (secp256k1_pubkey *) emalloc(sizeof(secp256k1_pubkey));
    result = secp256k1_ec_pubkey_combine(ctx, combined, pubkeys, array_count);
    if (result) {
        zval_dtor(zPubkeyCombined);
        ZVAL_RES(zPubkeyCombined, zend_register_resource(combined, le_secp256k1_pubkey));
    } else {
        // free when operation fails, won't return this resource
        efree(combined);
    }
    efree(pubkeys);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto resource secp256k1_scratch_space_create(resource context, long size)
 * Return a pointer to a scratch space. Some extra bytes are required for accounting. */
PHP_FUNCTION(secp256k1_scratch_space_create)
{
    zval * zCtx, *zScratch;
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    zend_long size;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &zCtx, &size) == FAILURE) {
        return;
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        return;
    }

    scratch = secp256k1_scratch_space_create(ctx, (size_t) size);

    secp256k1_scratch_space_wrapper* scratch_wrap;
    scratch_wrap = emalloc(sizeof(secp256k1_scratch_space_wrapper));
    scratch_wrap->ctx = ctx;
    scratch_wrap->scratch = scratch;

    RETURN_RES(zend_register_resource(scratch_wrap, le_secp256k1_scratch_space));
}
/* }}} */

/* {{{ proto bool secp256k1_scratch_space_destroy(resource context, resource scratch)
 * Destroy a secp256k1 scratch space object. */
PHP_FUNCTION(secp256k1_scratch_space_destroy)
{
    zval *zCtx, *zScratch;
    secp256k1_context *ctx;
    secp256k1_scratch_space_wrapper *scratch_wrap;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rr", &zCtx, &zScratch) == FAILURE) {
        RETURN_FALSE;
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_FALSE;
    }

    if ((scratch_wrap = php_get_secp256k1_scratch_space(zScratch)) == NULL) {
        RETURN_FALSE;
    }

    zend_list_close(Z_RES_P(zScratch));
    RETURN_TRUE;
}
/* }}} */

// zAlgo16 is interpreted as null|string, and we assume the comes
// from a function enforcing this convention. if it is a string type,
// the length must equal 16 or the function returns a negative result.
static int php_nonce_function_extract_algo(zval *zAlgo16, unsigned char **algo16)
{
    switch (Z_TYPE_P(zAlgo16)) {
        case IS_STRING:
            if (Z_STRLEN_P(zAlgo16) != 16) {
                return 0;
            }
            *algo16 = (unsigned char *) Z_STRVAL_P(zAlgo16);
            return 1;
        default:
            *algo16 = NULL;
            return 1;
    }
}

// zData may be any type, however this function is only used in the rfc6979
// and schnorrsig nonce functions, so it returns a negative result if
// the value is not NULL or a string. if it's a string value, it's length
// must be 32 bytes.
static int php_nonce_function_extract_data(zval *zData, unsigned char **data)
{
    // read arbitrary data pointer. enforce expectations of secp256k1_nonce_function_bipschnorr.
    switch (Z_TYPE_P(zData)) {
        case IS_STRING:
            if (Z_STRLEN_P(zData) != 32) {
                return 0;
            }
            *data = (unsigned char *) Z_STRVAL_P(zData);
            return 1;
        case IS_NULL:
            *data = NULL;
            return 1;
        default:
            // rfc6979 expects a 32byte string or NULL.
            return 0;
    }
}

// php_nonce_function_rfc6979 provides a PHP-typed analog for secp256k1_nonce_function_rfc6979.
static int php_nonce_function_rfc6979(zval *zNonce32, zend_string *zMsg32, zend_string *zKey32, zval *zAlgo16, zval *zData, unsigned int attempt)
{
    unsigned char *nonce32;
    unsigned char *algo16 = NULL;
    unsigned char *data = NULL;
    int result;

    if (!php_nonce_function_extract_algo(zAlgo16, &algo16)) {
        return 0;
    } else if (!php_nonce_function_extract_data(zData, &data)) {
        return 0;
    }

    nonce32 = emalloc(32);
    result = secp256k1_nonce_function_rfc6979(nonce32, (unsigned char *)zMsg32->val,
                                              (unsigned char *)zKey32->val, algo16, data, attempt);
    if (result) {
        zval_dtor(zNonce32);
        ZVAL_STRINGL(zNonce32, (const char *) nonce32, 32);
    } else {
        efree(nonce32);
    }

    return result;
}

/* {{{ proto long secp256k1_nonce_function_rfc6979(string &nonce32, string msg32, string key32, string algo16, data, long attempt)
 * An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
 * If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
 * extra entropy. */
PHP_FUNCTION(secp256k1_nonce_function_rfc6979)
{
    zval *zNonce32;
    zend_string *zMsg32, *zKey32;
    zval *zAlgo16 = NULL, *zData = NULL;
    long attempt;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/SSzzl", &zNonce32, &zMsg32, &zKey32, &zAlgo16, &zData, &attempt) == FAILURE) {
        RETURN_LONG(0);
    }

    result = php_nonce_function_rfc6979(zNonce32, zMsg32, zKey32, zAlgo16, zData, (unsigned int) attempt);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto long secp256k1_nonce_function_default(string &nonce32, string msg32, string key32, string algo16, data, long attempt)
 * A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979). */
PHP_FUNCTION(secp256k1_nonce_function_default)
{
    int result;
    zval *zNonce32;
    zend_string *zMsg32, *zKey32;
    zval *zAlgo16 = NULL, *zData = NULL;
    long attempt;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/SSzzl", &zNonce32, &zMsg32, &zKey32, &zAlgo16, &zData, &attempt) == FAILURE) {
        RETURN_LONG(0);
    }

    result = php_nonce_function_rfc6979(zNonce32, zMsg32, zKey32, zAlgo16, zData, (unsigned int) attempt);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_xonly_pubkey_create(resource context, resource &pubKey, string key32)
 * Compute the schnorrsig public key for a secret key. */
PHP_FUNCTION(secp256k1_xonly_pubkey_create)
{
    zval *zCtx;
    zval *zPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey *pubkey;
    zend_string *seckey;
    zend_resource *pubKeyResource;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zPubKey, &seckey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_pubkey_create(): Parameter 2 should be 32 bytes");
        return;
    }

    pubkey = (secp256k1_xonly_pubkey *) emalloc(sizeof(secp256k1_xonly_pubkey));
    result = secp256k1_xonly_pubkey_create(ctx, pubkey, (unsigned char *)seckey->val);
    if (result) {
        zval_dtor(zPubKey);
        ZVAL_RES(zPubKey, zend_register_resource(pubkey, le_secp256k1_xonly_pubkey));
    } else {
        // only free when operation fails, won't return this resource
        efree(pubkey);
    }

    RETURN_LONG(result);
}

/* {{{ proto int secp256k1_xonly_pubkey_parse(resource secp256k1_context, resource &pubKey, string pubKeyIn)
 * Parse a 32-byte public key into the secp256k1_xonly_pubkey object. */
PHP_FUNCTION(secp256k1_xonly_pubkey_parse)
{
    zval *zCtx, *zSchnorrSigPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey *pubkey;
    zend_string *pubkeyin;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSchnorrSigPubKey, &pubkeyin) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    } else if (pubkeyin->len != 32) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_pubkey_parse(): Parameter 3 should be 32 bytes");
        return;
    }

    pubkey = (secp256k1_xonly_pubkey *) emalloc(sizeof(secp256k1_xonly_pubkey));
    result = secp256k1_xonly_pubkey_parse(ctx, pubkey, (unsigned char *)pubkeyin->val);
    if (result) {
        zval_dtor(zSchnorrSigPubKey);
        ZVAL_RES(zSchnorrSigPubKey, zend_register_resource(pubkey, le_secp256k1_xonly_pubkey));
    } else {
        // only free when operation fails, won't return this resource
        efree(pubkey);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_xonly_pubkey_serialize(resource context, string &output32, resource pubKey)
 * Serialize a pubkey object into a serialized byte sequence. */
PHP_FUNCTION(secp256k1_xonly_pubkey_serialize)
{
    zval *zCtx, *zPubOut, *zSchnorrSigPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey * pubkey;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zPubOut, &zSchnorrSigPubKey) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    } else if ((pubkey = php_get_secp256k1_xonly_pubkey(zSchnorrSigPubKey)) == NULL) {
        RETURN_LONG(0);
    }

    unsigned char pubkeyout[32];
    result = secp256k1_xonly_pubkey_serialize(ctx, pubkeyout, pubkey);

    zval_dtor(zPubOut);
    ZVAL_STRINGL(zPubOut, (char *)&pubkeyout, 32);

    RETURN_LONG(result);
}
/* }}} */


/* {{{ proto int secp256k1_xonly_pubkey_from_pubkey(resource context, resource &xonly_pubkey, int &sign, resource pubkey)
 * Convert a recoverable signature into a normal signature. */
PHP_FUNCTION(secp256k1_xonly_pubkey_from_pubkey)
{
    zval *zCtx, *zXOnlyPubKey, *zSign, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey *xonly_pubkey;
    secp256k1_pubkey *pubkey;
    int sign;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/z/r", &zCtx, &zXOnlyPubKey, &zSign, &zPubKey) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(0);
    }

    xonly_pubkey = emalloc(sizeof(secp256k1_xonly_pubkey));
    result = secp256k1_xonly_pubkey_from_pubkey(ctx, xonly_pubkey, &sign, pubkey);
    if (result) {
        zval_dtor(zXOnlyPubKey);
        ZVAL_RES(zXOnlyPubKey, zend_register_resource(xonly_pubkey, le_secp256k1_xonly_pubkey));
        zval_dtor(zSign);
        ZVAL_LONG(zSign, sign);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_xonly_privkey_tweak_add(resource context, string &key32, string tweak32)
 * Tweak a private key by adding tweak to it. */
PHP_FUNCTION(secp256k1_xonly_privkey_tweak_add)
{
    zval *zCtx, *zSecKey;
    secp256k1_context *ctx;
    zend_string *zTweak;
    unsigned char *tweak;
    unsigned char newseckey[SECRETKEY_LENGTH];
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSecKey, &zTweak) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    }

    if (Z_STRLEN_P(zSecKey) != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_privkey_tweak_add(): Parameter 2 should be 32 bytes");
        return;
    } else if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_privkey_tweak_add(): Parameter 3 should be 32 bytes");
        return;
    }

    memcpy(newseckey, Z_STRVAL_P(zSecKey), SECRETKEY_LENGTH);
    result = secp256k1_xonly_privkey_tweak_add(ctx, newseckey, (unsigned char *) zTweak->val);
    if (result) {
        zval_dtor(zSecKey);
        ZVAL_STRINGL(zSecKey, (const char *) newseckey, SECRETKEY_LENGTH);
    }
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_xonly_pubkey_tweak_add(resource context, resource &output_pubkey, resource internal_pubkey, string tweak32)
 * Tweak a public key by adding tweak times the generator to it. */
PHP_FUNCTION(secp256k1_xonly_pubkey_tweak_add)
{
    zval *zCtx, *zOutputPubKey, *zIsPositive, *zInternalPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey *output_pubkey, *internal_pubkey;
    zend_string *zTweak;
    int is_positive;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/z/rS", &zCtx, &zOutputPubKey, &zIsPositive, &zInternalPubKey, &zTweak) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    } else if ((internal_pubkey = php_get_secp256k1_xonly_pubkey(zInternalPubKey)) == NULL) {
        RETURN_LONG(0);
    }

    if (zTweak->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_pubkey_tweak_add(): Parameter 5 should be 32 bytes");
        return;
    }

    output_pubkey = emalloc(sizeof(secp256k1_xonly_pubkey));
    result = secp256k1_xonly_pubkey_tweak_add(ctx, output_pubkey, &is_positive, internal_pubkey, (unsigned char *)zTweak->val);
    if (result) {
        zval_dtor(zOutputPubKey);
        ZVAL_RES(zOutputPubKey, zend_register_resource(output_pubkey, le_secp256k1_xonly_pubkey));
        zval_dtor(zIsPositive);
        ZVAL_LONG(zIsPositive, is_positive);
    } else {
        efree(output_pubkey);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_xonly_pubkey_tweak_verify(resource context, resource output_pubkey, resource internal_pubkey, string tweak32)
 * Tweak a public key by adding tweak times the generator to it. */
PHP_FUNCTION(secp256k1_xonly_pubkey_tweak_verify)
{
    zval *zCtx, *zOutputPubKey, *zInternalPubKey;
    secp256k1_context *ctx;
    secp256k1_xonly_pubkey *output_pubkey, *internal_pubkey;
    zend_long is_positive;
    zend_string *zTweak32;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrlrS", &zCtx, &zOutputPubKey, &is_positive, &zInternalPubKey, &zTweak32) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    } else if ((output_pubkey = php_get_secp256k1_xonly_pubkey(zOutputPubKey)) == NULL) {
        RETURN_LONG(0);
    }  else if ((internal_pubkey = php_get_secp256k1_xonly_pubkey(zInternalPubKey)) == NULL) {
        RETURN_LONG(0);
    }

    if (zTweak32->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_xonly_pubkey_tweak_verify(): Parameter 4 should be 32 bytes");
        return;
    }

    result = secp256k1_xonly_pubkey_tweak_verify(ctx, output_pubkey, (int)is_positive, internal_pubkey, (unsigned char *)zTweak32->val);

    RETURN_LONG(result);
}
/* }}} */

/* Begin recovery module functions */
#ifdef SECP256K1_MODULE_RECOVERY

/* {{{ proto int secp256k1_ecdsa_recoverable_signature_parse_compact(resource context, resource &sig, string sig64, int recid)
 * Parse a compact ECDSA signature (64 bytes + recovery id). */
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_parse_compact)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_recoverable_signature *sig;
    zend_string *zSig64In;
    long recid;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/Sl", &zCtx, &zSig, &zSig64In, &recid) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (zSig64In->len != 64) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ecdsa_recoverable_signature_parse_compact(): Parameter 3 should be 64 bytes");
        return;
    }

    if (!(recid >= 0 && recid <= 3)) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ecdsa_recoverable_signature_parse_compact(): recid should be between 0-3");
        return;
    }

    sig = emalloc(sizeof(secp256k1_ecdsa_recoverable_signature));
    result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, sig, (unsigned char *)zSig64In->val, recid);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(sig, le_secp256k1_recoverable_sig));
    } else {
        // free when operation fails, won't return this resource
        efree(sig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_recoverable_signature_convert(resource context, resource &normalSigOut, resource sigIn)
 * Convert a recoverable signature into a normal signature. */
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_convert)
{
    zval *zCtx, *zNormalSig, *zRecoverableSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature * nSig;
    secp256k1_ecdsa_recoverable_signature * rSig;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zNormalSig, &zRecoverableSig) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((rSig = php_get_secp256k1_ecdsa_recoverable_signature(zRecoverableSig)) == NULL) {
        RETURN_LONG(result);
    }

    nSig = emalloc(sizeof(secp256k1_ecdsa_recoverable_signature));
    result = secp256k1_ecdsa_recoverable_signature_convert(ctx, nSig, rSig);

    zval_dtor(zNormalSig);
    ZVAL_RES(zNormalSig, zend_register_resource(nSig, le_secp256k1_sig));
    // convert() can't fail, so we'll always return the resource here

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_recoverable_signature_serialize_compact(resource context, string &sigOut, int &recid, resource sig)
 * Serialize an ECDSA signature in compact format (64 bytes + recovery id). */
PHP_FUNCTION(secp256k1_ecdsa_recoverable_signature_serialize_compact)
{
    zval *zCtx, *zRecSig, *zSigOut, *zRecId;
    secp256k1_context *ctx;
    secp256k1_ecdsa_recoverable_signature *recsig;
    unsigned char sig[COMPACT_SIGNATURE_LENGTH];
    int result = 0, recid;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/z/r", &zCtx, &zSigOut, &zRecId, &zRecSig) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((recsig = php_get_secp256k1_ecdsa_recoverable_signature(zRecSig)) == NULL) {
        RETURN_LONG(result);
    }

    result = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig, &recid, recsig);

    zval_dtor(zSigOut);
    ZVAL_STRINGL(zSigOut, (const char *) sig, COMPACT_SIGNATURE_LENGTH);

    zval_dtor(zRecId);
    ZVAL_LONG(zRecId, recid);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_sign_recoverable(resource context, resource &sig, string msg32, string key32)
 * Create a recoverable ECDSA signature. */
PHP_FUNCTION(secp256k1_ecdsa_sign_recoverable)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    zend_string *msg32, *seckey;
    secp256k1_ecdsa_recoverable_signature *newsig;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/SS", &zCtx, &zSig, &msg32, &seckey) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (msg32->len != HASH_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ecdsa_sign_recoverable(): Parameter 2 should be 32 bytes");
        return;
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_ecdsa_sign_recoverable(): Parameter 3 should be 32 bytes");
        return;
    }

    newsig = emalloc(sizeof(secp256k1_ecdsa_recoverable_signature));
    result = secp256k1_ecdsa_sign_recoverable(ctx, newsig, (const unsigned char *) msg32->val, (const unsigned char *) seckey->val, 0, 0);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(newsig, le_secp256k1_recoverable_sig));
    } else {
        // free when operation fails, won't return this resource
        efree(newsig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_recover(resource context, resource &pubKey, resource recSig, string msg32)
 * Recover an ECDSA public key from a signature. */
PHP_FUNCTION(secp256k1_ecdsa_recover)
{
    zval *zCtx, *zPubKey, *zSig;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    secp256k1_ecdsa_recoverable_signature *sig;
    zend_string *msg32;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rS", &zCtx, &zPubKey, &zSig, &msg32) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((sig = php_get_secp256k1_ecdsa_recoverable_signature(zSig)) == NULL) {
        RETURN_LONG(result);
    }

    pubkey = (secp256k1_pubkey *) emalloc(sizeof(secp256k1_pubkey));
    result = secp256k1_ecdsa_recover(ctx, pubkey, sig, (const unsigned char *) msg32->val);
    if (result) {
        zval_dtor(zPubKey);
        ZVAL_RES(zPubKey, zend_register_resource(pubkey, le_secp256k1_pubkey));
    } else {
        // free when operation fails, won't return this resource
        efree(pubkey);
    }

    RETURN_LONG(result);
}
/* }}} */

#endif
/* End recovery module functions */

/* Begin EcDH module functions */
#ifdef SECP256K1_MODULE_ECDH

typedef struct php_secp256k1_hash_function_data {
    zend_fcall_info* fci;
    zend_fcall_info_cache* fcc;
    long output_len;
    zval* data;
} php_secp256k1_hash_function_data;

static int php_secp256k1_hash_function(unsigned char *output, const unsigned char *x,
                            const unsigned char *y, void *data) {
    php_secp256k1_hash_function_data* callback;
    zend_string* output_str;
    zval retval, zvalout;
    zval args[4];
    int result, i;

    callback = (php_secp256k1_hash_function_data*) data;
    callback->fci->size = sizeof(*(callback->fci));
    callback->fci->object = NULL;
    callback->fci->retval = &retval;
    callback->fci->params = args;
    callback->fci->param_count = 3;
    ZVAL_NEW_STR(&zvalout, zend_string_init("", 0, 0));

    // wrt ownership, args 0, 1, & 2 are managed by us in order to
    // receive the result, and pass in the x & y parameters.
    // arg 3 is owned by the caller of secp256k1_ecdh.
    ZVAL_NEW_REF(&args[0], &zvalout);
    ZVAL_STR(&args[1], zend_string_init((const char *) x, 32, 0));
    ZVAL_STR(&args[2], zend_string_init((const char *) y, 32, 0));
    if (callback->data != NULL) {
        callback->fci->param_count++;
        zval* data = callback->data;
        args[3] = *data;
    }

    result = zend_call_function(callback->fci, callback->fcc) == SUCCESS;

    // check function invocation result
    if (result) {
        // now respect return value
        if (Z_TYPE(retval) == IS_FALSE) {
            result = 0;
        } else if (Z_TYPE(retval) == IS_TRUE) {
            result = 1;
        } else if (Z_TYPE(retval) == IS_LONG) {
            result = Z_LVAL(retval);
        }
    }

    // ensure the resulting string has a length matching callback->output_len,
    // as in secp256k1_ecdh we allocate exactly that many bytes. if the length
    // doesn't match, cancel the operation
    if (result) {
        output_str = Z_STR_P(Z_REFVAL(args[0]));
        if (output_str->len != callback->output_len) {
            result = 0;
        }
    }

    // callback OK & length correct
    if (result) {
        memcpy(output, output_str->val, output_str->len);
    }

    // zval_dtor on our args. arg 3 is managed elsewhere.
    for (i = 0; i < 3; i++) {
        zval_dtor(&args[i]);
    }

    return result;
}

/* {{{ proto int secp256k1_ecdh(resource context, string &result, resource pubKey, string key32, callable hashfp, int output_len, data)
 * Compute an EC Diffie-Hellman secret in constant time. */
PHP_FUNCTION(secp256k1_ecdh)
{
    zval *zCtx, *zResult, *zPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *pubkey;
    zend_string *privKey;
    zval* data = NULL;
    long output_len = 32;
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
    php_secp256k1_hash_function_data callback;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rS|flz",
        &zCtx, &zResult, &zPubKey, &privKey, &fci, &fcc, &output_len, &data) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    // in C codebases, the ecdh var would be allocated before calling secp256k1_ecdh.
    // PHP does not have a way pre-allocate memory in this way, so we allocate it
    // here. where a custom hashfp is provided, the output_len must equal the size of
    // the data to be written by the hashfp. ex, 32 bytes if a sha256 hash is returned.
    unsigned char resultChars[output_len];
    memset(resultChars, 0, output_len);
    if (ZEND_NUM_ARGS() > 4) {
        callback.fci = &fci;
        callback.fcc = &fcc;
        callback.output_len = output_len;
        callback.data = data;
        result = secp256k1_ecdh(ctx, resultChars, pubkey, (unsigned char *) privKey->val, php_secp256k1_hash_function, (void*) &callback);
    } else {
        result = secp256k1_ecdh(ctx, resultChars, pubkey, (unsigned char *) privKey->val, NULL, NULL);
    }

    if (result) {
        zval_dtor(zResult);
        ZVAL_STRINGL(zResult, (char *) resultChars, output_len);
    }

    RETURN_LONG(result);
}
/* }}} */

#endif
/* End EcDH module functions */

/* Begin schnorr module functions */
#ifdef SECP256K1_MODULE_SCHNORRSIG

/* {{{ proto int secp256k1_schnorrsig_serialize(resource context, string &result, resource schnorrsig)
 * Serialize a Schnorr signature. */
PHP_FUNCTION(secp256k1_schnorrsig_serialize)
{
    zval *zCtx, *zSchnorrSig, *zSigOut;
    secp256k1_context *ctx;
    secp256k1_schnorrsig *sig;
    unsigned char sigout[COMPACT_SIGNATURE_LENGTH];
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/r", &zCtx, &zSigOut, &zSchnorrSig) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    }

    if ((sig = php_get_secp256k1_schnorr_signature(zSchnorrSig)) == NULL) {
        RETURN_LONG(0);
    }

    result = secp256k1_schnorrsig_serialize(ctx, sigout, sig);
    if (result) {
        zval_dtor(zSigOut);
        ZVAL_STRINGL(zSigOut, (const char *)&sigout, COMPACT_SIGNATURE_LENGTH);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_schnorrsig_parse(resource ctx, resource &sig, string sigIn)
 * Parse a Schnorr signature. */
PHP_FUNCTION(secp256k1_schnorrsig_parse)
{
    zval *zCtx, *zSchnorrSig;
    secp256k1_context *ctx;
    secp256k1_schnorrsig *sig;
    zend_string *sigin;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/S", &zCtx, &zSchnorrSig, &sigin) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    }

    if (sigin->len != COMPACT_SIGNATURE_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC, "secp256k1_schnorrsig_parse(): Parameter 3 should be 64 bytes");
        return;
    }

    sig = (secp256k1_schnorrsig *) emalloc(sizeof(secp256k1_schnorrsig));
    result = secp256k1_schnorrsig_parse(ctx, sig, (const unsigned char *) sigin->val);
    if (result) {
        zval_dtor(zSchnorrSig);
        ZVAL_RES(zSchnorrSig, zend_register_resource(sig, le_secp256k1_schnorrsig));
    } else {
        // only free when operation fails, won't return this resource
        efree(sig);
    }

    RETURN_LONG(result);
}
/* }}} */


/* {{{ proto int secp256k1_schnorrsig_sign(resource context, resource &sig, string msg32, string key32)
 * Create an ECDSA signature. */
PHP_FUNCTION (secp256k1_schnorrsig_sign)
{
    zval *zCtx, *zSig, *zNData = NULL;
    zend_string *msg32, *seckey;
    secp256k1_context *ctx;
    secp256k1_schnorrsig *newsig;
    secp256k1_nonce_function noncefp = NULL;
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
    php_secp256k1_nonce_function_data calldata;
    void* ndata = NULL;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/SS|fz",
        &zCtx, &zSig, &msg32, &seckey, &fci, &fcc, &zNData) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if (msg32->len != HASH_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0
        TSRMLS_CC, "secp256k1_schnorrsig_sign(): Parameter 3 should be 32 bytes");
        return;
    }

    if (seckey->len != SECRETKEY_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0
        TSRMLS_CC, "secp256k1_schnorrsig_sign(): Parameter 4 should be 32 bytes");
        return;
    }

    if (ZEND_NUM_ARGS() > 4) {
        noncefp = php_secp256k1_nonce_function_callback;
        calldata.fci = &fci;
        calldata.fcc = &fcc;
        if (zNData == NULL) {
            calldata.data = NULL;
        } else {
            calldata.data = zNData;
        }
        ndata = (void *) &calldata;
    }

    newsig = (secp256k1_schnorrsig *) emalloc(sizeof(secp256k1_schnorrsig));
    result = secp256k1_schnorrsig_sign(ctx, newsig,
        (unsigned char *) msg32->val, (unsigned char *) seckey->val, noncefp, ndata);
    if (result) {
        zval_dtor(zSig);
        ZVAL_RES(zSig, zend_register_resource(newsig, le_secp256k1_schnorrsig));
    } else {
        // only free when operation fails, won't return this resource
        efree(newsig);
    }

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_schnorrsig_verify(resource context, resource sig, string msg32, resource pubKey)
 * Verify a Schnorr signature. */
PHP_FUNCTION(secp256k1_schnorrsig_verify) {
    zval *zCtx, *zSchnorrSig, *zXOnlyPubKey;
    secp256k1_context *ctx;
    secp256k1_schnorrsig *sig;
    secp256k1_xonly_pubkey *pubkey;
    zend_string *msg32;
    int result;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrSr", &zCtx, &zSchnorrSig, &msg32, &zXOnlyPubKey) == FAILURE) {
        RETURN_LONG(0);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(0);
    } else if ((sig = php_get_secp256k1_schnorr_signature(zSchnorrSig)) == NULL) {
        RETURN_LONG(0);
    } else if ((pubkey = php_get_secp256k1_xonly_pubkey(zXOnlyPubKey)) == NULL) {
        RETURN_LONG(0);
    }

    if (msg32->len != HASH_LENGTH) {
        zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0
        TSRMLS_CC, "secp256k1_schnorrsig_verify(): Parameter 3 should be 32 bytes");
        return;
    }

    result = secp256k1_schnorrsig_verify(ctx, sig, (unsigned char *) msg32->val, pubkey);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_schnorrsig_verify(resource context, resource scratch, array sigs, array msg32s, array keys, long numsigs)
 * Verify a Schnorr signature. */
PHP_FUNCTION(secp256k1_schnorrsig_verify_batch)
{
    zval *zCtx, *zScratch, *zSigArray, *zMsg32Array, *zXOnlyPubKeyArray, *arrayZval;
    zend_long numsigs;
    secp256k1_context *ctx;
    secp256k1_scratch_space_wrapper *scratch_wrap;
    HashTable *arr_hash;
    const secp256k1_schnorrsig **sigs, *sig;
    const secp256k1_xonly_pubkey ** pubkeys, *pubkey;
    const unsigned char * *msg32s, *msg32;
    zend_string *arrayKeyStr;

    size_t array_count;
    int result = 0, i = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rraaal",
        &zCtx, &zScratch, &zSigArray, &zMsg32Array, &zXOnlyPubKeyArray, &numsigs) == FAILURE) {
        RETURN_LONG(result);
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((scratch_wrap = php_get_secp256k1_scratch_space(zScratch)) == NULL) {
        RETURN_LONG(result);
    }

    if ((size_t) numsigs != (size_t) zend_hash_num_elements(Z_ARRVAL_P(zXOnlyPubKeyArray)) ||
        (size_t) numsigs != (size_t) zend_hash_num_elements(Z_ARRVAL_P(zMsg32Array)) ||
        (size_t) numsigs != (size_t) zend_hash_num_elements(Z_ARRVAL_P(zSigArray))) {
        RETURN_LONG(result);
    }

    sigs = emalloc(sizeof(secp256k1_schnorrsig *) * numsigs);
    arr_hash = Z_ARRVAL_P(zSigArray);
    ZEND_HASH_FOREACH_KEY_VAL(arr_hash, i, arrayKeyStr, arrayZval) {
        if ((sig = php_get_secp256k1_schnorr_signature(arrayZval)) == NULL) {
            efree(sigs);
            RETURN_LONG(result);
        }
        sigs[i++] = sig;
    } ZEND_HASH_FOREACH_END();

    msg32s = emalloc(sizeof(unsigned char *) * numsigs);
    arr_hash = Z_ARRVAL_P(zMsg32Array);
    ZEND_HASH_FOREACH_KEY_VAL(arr_hash, i, arrayKeyStr, arrayZval) {
        if (Z_TYPE_P(arrayZval) != IS_STRING || Z_STRLEN_P(arrayZval) != 32) {
            efree(sigs);
            efree(msg32s);
            RETURN_LONG(result);
        }
        msg32s[i++] = (unsigned char *) Z_STRVAL_P(arrayZval);
    } ZEND_HASH_FOREACH_END();

    pubkeys = emalloc(sizeof(secp256k1_xonly_pubkey *) * numsigs);
    arr_hash = Z_ARRVAL_P(zXOnlyPubKeyArray);
    ZEND_HASH_FOREACH_KEY_VAL(arr_hash, i, arrayKeyStr, arrayZval) {
        if ((pubkey = php_get_secp256k1_xonly_pubkey(arrayZval)) == NULL) {
            efree(sigs);
            efree(msg32s);
            efree(pubkeys);
            RETURN_LONG(result);
        }
        pubkeys[i++] = pubkey;
    } ZEND_HASH_FOREACH_END();

    result = secp256k1_schnorrsig_verify_batch(ctx, scratch_wrap->scratch,
                                sigs, msg32s, pubkeys, numsigs);
    efree(msg32s);
    efree(sigs);
    efree(pubkeys);

    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto long secp256k1_nonce_function_bipschnorr(string &nonce32, string msg32, string key32, string algo16, data, long attempt)
 * An implementation of the nonce generation function as defined in BIP-schnorr.
 * If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
 * extra entropy. */
PHP_FUNCTION(secp256k1_nonce_function_bipschnorr)
{
    int result;
    zval *zNonce32;
    zend_string *zMsg32, *zKey32;
    zval *zAlgo16 = NULL, *zData = NULL;
    unsigned char *nonce32;
    unsigned char *algo16 = NULL;
    unsigned char *data = NULL;
    long attempt;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/SSzzl", &zNonce32, &zMsg32, &zKey32, &zAlgo16, &zData, &attempt) == FAILURE) {
        RETURN_LONG(0);
    }

    if (!php_nonce_function_extract_algo(zAlgo16, &algo16)) {
        RETURN_LONG(0);
    } else if (!php_nonce_function_extract_data(zData, &data)) {
        RETURN_LONG(0);
    }

    nonce32 = emalloc(32);
    result = secp256k1_nonce_function_bipschnorr(nonce32, (unsigned char *)zMsg32->val,
                                              (unsigned char *)zKey32->val, algo16, data, attempt);
    if (result) {
        zval_dtor(zNonce32);
        ZVAL_STRINGL(zNonce32, (const char *) nonce32, 32);
    } else {
        efree(nonce32);
    }
    RETURN_LONG(result);
}
/* }}} */

#endif
/* End schnorr module functions */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

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

static zend_class_entry *spl_ce_InvalidArgumentException;

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

        // secp256k1_recovery.h
        PHP_FE(secp256k1_ecdsa_recoverable_signature_parse_compact, arginfo_secp256k1_ecdsa_recoverable_signature_parse_compact)
        PHP_FE(secp256k1_ecdsa_recoverable_signature_convert, arginfo_secp256k1_ecdsa_recoverable_signature_convert)
        PHP_FE(secp256k1_ecdsa_recoverable_signature_serialize_compact, arginfo_secp256k1_ecdsa_recoverable_signature_serialize_compact)
        PHP_FE(secp256k1_ecdsa_sign_recoverable,             arginfo_secp256k1_ecdsa_sign_recoverable)
        PHP_FE(secp256k1_ecdsa_recover,                      arginfo_secp256k1_ecdsa_recover)

        // secp256k1_ecdh.h
        PHP_FE(secp256k1_ecdh,                               arginfo_secp256k1_ecdh)

        PHP_FE_END	/* Must be the last line in resource_functions[] */
};
/* }}} */

/* resource numbers */
static int le_secp256k1_ctx;
static int le_secp256k1_pubkey;
static int le_secp256k1_sig;
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

static void secp256k1_recoverable_sig_dtor(zend_resource * rsrc TSRMLS_DC)
{
    secp256k1_ecdsa_recoverable_signature *sig = (secp256k1_ecdsa_recoverable_signature*) rsrc->ptr;
    if (sig) {
        efree(sig);
    }
}

// attempt to read a sec256k1_context* from the provided resource zval
static secp256k1_context* php_get_secp256k1_context(zval* pcontext) {
    return (secp256k1_context *)zend_fetch_resource2_ex(pcontext, SECP256K1_CTX_RES_NAME, le_secp256k1_ctx, -1);
}

// attempt to read a sec256k1_ecdsa_signature* from the provided resource zval
static secp256k1_ecdsa_signature* php_get_secp256k1_ecdsa_signature(zval *psig) {
    return (secp256k1_ecdsa_signature *)zend_fetch_resource2_ex(psig, SECP256K1_SIG_RES_NAME, le_secp256k1_sig, -1);
}

// attempt to read a sec256k1_ecdsa_recoverable_signature* from the provided resource zval
static secp256k1_ecdsa_recoverable_signature* php_get_secp256k1_ecdsa_recoverable_signature(zval *precsig) {
    return (secp256k1_ecdsa_recoverable_signature *)zend_fetch_resource2_ex(precsig, SECP256K1_RECOVERABLE_SIG_RES_NAME, le_secp256k1_recoverable_sig, -1);
}

// attempt to read a sec256k1_pubkey* from the provided resource zval
static secp256k1_pubkey* php_get_secp256k1_pubkey(zval *pkey) {
    return (secp256k1_pubkey *)zend_fetch_resource2_ex(pkey, SECP256K1_PUBKEY_RES_NAME, le_secp256k1_pubkey, -1);
}

PHP_MINIT_FUNCTION(secp256k1) {
    le_secp256k1_ctx = zend_register_list_destructors_ex(secp256k1_ctx_dtor, NULL, SECP256K1_CTX_RES_NAME, module_number);
    le_secp256k1_pubkey = zend_register_list_destructors_ex(secp256k1_pubkey_dtor, NULL, SECP256K1_PUBKEY_RES_NAME, module_number);
    le_secp256k1_sig = zend_register_list_destructors_ex(secp256k1_sig_dtor, NULL, SECP256K1_SIG_RES_NAME, module_number);
    le_secp256k1_recoverable_sig = zend_register_list_destructors_ex(secp256k1_recoverable_sig_dtor, NULL, SECP256K1_RECOVERABLE_SIG_RES_NAME, module_number);

    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_CONTEXT", SECP256K1_CTX_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_PUBKEY", SECP256K1_PUBKEY_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_SIG", SECP256K1_SIG_RES_NAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SECP256K1_TYPE_RECOVERABLE_SIG", SECP256K1_RECOVERABLE_SIG_RES_NAME, CONST_CS | CONST_PERSISTENT);

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
    /*
    ZEND_INIT_MODULE_GLOBALS(secp256k1, php_secp256k1_init_globals, NULL);
     */
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
            seed32 = Z_STRVAL_P(zSeed);
        } else if (Z_TYPE_P(zSeed) != IS_NULL) {
            zend_throw_exception_ex(spl_ce_InvalidArgumentException, 0 TSRMLS_CC,
                    "secp256k1_context_randomize(): Parameter 2 should be a 32 byte string, or null");
            return;
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
    result = secp256k1_ecdsa_signature_parse_der(ctx, sig, sigin->val, sigin->len);
    if (result == 1) {
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
    unsigned char sigout[sigoutlen];
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
    if (result == 1) {
        zval_dtor(zSigOut);
        ZVAL_STRINGL(zSigOut, (char*)&sigout, sigoutlen);
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
    result = secp256k1_ecdsa_signature_parse_compact(ctx, sig, (unsigned char*) input64->val);
    if (result == 1) {
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
    ZVAL_STRINGL(zSigOut, (char*) &sigOut, COMPACT_SIGNATURE_LENGTH);
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
    result = ecdsa_signature_parse_der_lax(ctx, sig, sigin->val, sigin->len);
    if (result == 1) {
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

    result = secp256k1_ecdsa_verify(ctx, sig, msg32->val, pubkey);
    RETURN_LONG(result);
}
/* }}} */

/* {{{ proto int secp256k1_ecdsa_sign(resource context, resource &sig, string msg32, string key32)
 * Create an ECDSA signature. */
PHP_FUNCTION (secp256k1_ecdsa_sign)
{
    zval *zCtx, *zSig;
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature *newsig;
    zend_string *msg32, *seckey;
    int result = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/SS", &zCtx, &zSig, &msg32, &seckey) == FAILURE) {
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

    newsig = (secp256k1_ecdsa_signature *) emalloc(sizeof(secp256k1_ecdsa_signature));
    result = secp256k1_ecdsa_sign(ctx, newsig, msg32->val, seckey->val, NULL, NULL);
    if (result == 1) {
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

    result = secp256k1_ec_seckey_verify(ctx, seckey->val);

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
    if (result == 1) {
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
    if (result == 1) {
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

    pubkeylen = (flags & SECP256K1_EC_COMPRESSED != 0) ? PUBKEY_COMPRESSED_LENGTH : PUBKEY_UNCOMPRESSED_LENGTH;
    unsigned char pubkeyout[pubkeylen];
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
    ZVAL_STRINGL(zSecKey, newseckey, SECRETKEY_LENGTH);
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
    ZVAL_STRINGL(zSecKey, newseckey, SECRETKEY_LENGTH);
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
    zval *arr, *zCtx, *zPubkeyCombined, *arrayPubKey;
    secp256k1_context *ctx;
    secp256k1_pubkey *ptr, *combined;
    zend_string *arrayKeyStr;
    HashTable *arr_hash;
    HashPosition pointer;
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
    const secp256k1_pubkey * pubkeys[array_count];

    ZEND_HASH_FOREACH_KEY_VAL(arr_hash, i, arrayKeyStr, arrayPubKey) {
        if ((ptr = php_get_secp256k1_pubkey(arrayPubKey)) == NULL) {
            RETURN_LONG(result);
        }

        pubkeys[i++] = ptr;
    } ZEND_HASH_FOREACH_END();

    combined = (secp256k1_pubkey *) emalloc(sizeof(secp256k1_pubkey));
    result = secp256k1_ec_pubkey_combine(ctx, combined, pubkeys, array_count);
    if (result == 1) {
        zval_dtor(zPubkeyCombined);
        ZVAL_RES(zPubkeyCombined, zend_register_resource(combined, le_secp256k1_pubkey));
    } else {
        // free when operation fails, won't return this resource
        efree(combined);
    }

    RETURN_LONG(result);
}
/* }}} */

/* Begin recovery module functions */

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
    if (result == 1) {
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
    ZVAL_STRINGL(zSigOut, sig, COMPACT_SIGNATURE_LENGTH);

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
    result = secp256k1_ecdsa_sign_recoverable(ctx, newsig, msg32->val, seckey->val, 0, 0);
    if (result == 1) {
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
    result = secp256k1_ecdsa_recover(ctx, pubkey, sig, msg32->val);
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

/* End recovery module functions */

/* Begin EcDH module functions */

typedef struct php_callback {
    zend_fcall_info* fci;
    zend_fcall_info_cache* fcc;
    long output_len;
    zval* data;
} php_callback;

static int trigger_callback(unsigned char* output, const unsigned char *x,
                            const unsigned char* y, void *data) {
    php_callback* callback;

    callback = (php_callback*) data;
    zend_string* output_str;
    zval retval, zvalout;
    zval args[4];
    int result, i;
    int arg_count = (callback->data != NULL) ? 4 : 3;

    callback->fci->size = sizeof(*(callback->fci));
    callback->fci->object = NULL;
    callback->fci->retval = &retval;
    callback->fci->param_count = arg_count;
    callback->fci->params = args;

    ZVAL_NEW_STR(&zvalout, zend_string_init("", 0, 0));

    ZVAL_NEW_REF(&args[0], &zvalout);
    ZVAL_STR(&args[1], zend_string_init(x, 32, 0));
    ZVAL_STR(&args[2], zend_string_init(y, 32, 0));
    if (arg_count == 4) {
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

    // there's more! what if the length doesn't match? avoid.
    if (result) {
        output_str = Z_STR_P(Z_REFVAL(args[0]));
        if (output_str->len != callback->output_len) {
            result = 0;
        }
    }

    // callback OK & length correct
    if (result) {
        for (i = 0; i < output_str->len; i++) {
            output[i] = (unsigned char)output_str->val[i];
        }
    }

    zval_dtor(&args[0]);
    zval_dtor(&args[1]);
    zval_dtor(&args[2]);

    return result;
}

/* {{{ proto int secp256k1_ecdh(resource context, string &result, resource pubKey, string key32)
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
    php_callback callback;
    int result = 0;
    if (ZEND_NUM_ARGS() == 7) {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rS|flz",
            &zCtx, &zResult, &zPubKey, &privKey, &fci, &fcc, &output_len, &data) == FAILURE) {
            RETURN_LONG(result);
        }
    } else if (ZEND_NUM_ARGS() == 6) {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rS|fl", &zCtx, &zResult, &zPubKey, &privKey, &fci, &fcc, &output_len) == FAILURE) {
            RETURN_LONG(result);
        }
    } else {
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/rS", &zCtx, &zResult, &zPubKey, &privKey) == FAILURE) {
            RETURN_LONG(result);
        }
    }

    if ((ctx = php_get_secp256k1_context(zCtx)) == NULL) {
        RETURN_LONG(result);
    }

    if ((pubkey = php_get_secp256k1_pubkey(zPubKey)) == NULL) {
        RETURN_LONG(result);
    }

    if (ZEND_NUM_ARGS() < 5) {
        output_len = 32;
    }

    unsigned char resultChars[output_len];
    memset(resultChars, 0, output_len);
    if (ZEND_NUM_ARGS() > 4) {
        callback.fci = &fci;
        callback.fcc = &fcc;
        callback.output_len = output_len;
        callback.data = data;
        result = secp256k1_ecdh(ctx, resultChars, pubkey, privKey->val, trigger_callback, (void*) &callback);
    } else {
        result = secp256k1_ecdh(ctx, resultChars, pubkey, privKey->val, NULL, NULL);
    }
    if (result == 1) {
        zval_dtor(zResult);
        ZVAL_STRINGL(zResult, resultChars, output_len);
    }

    RETURN_LONG(result);
}
/* }}} */

/* End EcDH module functions */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

v0.2.0 release notes
====================

This is a major release, including several backwards compatibility breaks
with the v0.1.x branch. 

The minimum PHP version was bumped to 7.0, along with some API changes.

This is due to our extension use of parameter and return type declarations. Worth pointing out: adopting the type hints makes use without strict_types _more_ prone to type-coercion of similar values. Setting strict_types=1 is recommended as it prevents type coercion.

# API BC breaks

 - secp256k1_ec_pubkey_serialize
   * `bool $compressed` is replaced with `int $flags`. See `SECP256K1_EC_COMPRESSED` AND `SECP256K1_EC_UNCOMPRESSED`

 - secp256k1_ecdsa_recoverable_signature_serialize_compact 
   * The parameter listing of this function did not match upstream. The second parameter (the signature resource) has been moved to the 4rd parameter.
   
 - secp256k1_ecdsa_verify
   * In previous releases, this function would copy the signature and normalize it in place. In order to match the semantics of the upstream library, this responsibility is now on the caller of the function. 

# Documentation

The project now has a test harness ensuring our stubs files exactly match the API. Credits to php-extension-stubs-generator @sasezaki for the tool that made this possible!

Any time an API change occurs, the stubs file can be generated with `travis/generate_stubs.sh live`


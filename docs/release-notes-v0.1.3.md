v0.1.3 release notes
====================

This is a minor release, containing a number of bug fixes
ranging from minor to severe. It's recommended to upgrade
to v0.1.3 ASAP if you are using the modify-in-place functions
secp256k1_ec_privkey_tweak_{add,mul}.

Essentially, due to the copy-on-write operation of PHP, 
it seems the library could potentially overwrite references
to the zval (copy) passed to the function. So if a object
method returns a string property, on php nightly it seems
that something caused the value in the object to be modified
in addition to the value returned from the getter method.

So if you use deterministic key derivations based on these
methods, it could lead to the master key being modified in place
by a derivation, leading to incorrect _subsequent_ derivations.

# Testing dependencies
 - `phpunit/phpunit` & `symfony/yaml` were upgraded to more recent versions
 
# Testing 

 - Adds phpt tests (integrated with php-src's unit tests) for proper coverage tests, reached >99%
 - Tweak `Secp256k1EcdsaSignTest` so we can check signatures match the expected value
 
# Bugs:

 - Fix `secp256k1_ecdsa_signature normalize`, couldn't have been working before (f07fa96) 
 - `secp256k1_context_randomize` should check string size, and allow NULL too.
 - Fix bug in `secp256k1_context_destroy`, causing segfault on 7.1 (and greater) unit tests (f6a562a)
 - Critical: Fix `secp256k1_ec_privkey_tweak_add`, which on PHP nightly would modify all copies of the zval being modified... (778ffde)
 - Fixed inconsistent null/false return values in some error cases

# New features: 

 - Adds `secp256k1_ec_privkey_negate`, and `secp256k1_ec_pubkey_negate`
 - Adds `secp256k1_ecdsa_signature_serialize_compact` and `secp256k1_ecdsa_signature_parse_compact`

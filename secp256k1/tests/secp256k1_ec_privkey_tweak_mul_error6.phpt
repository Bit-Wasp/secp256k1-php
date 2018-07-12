--TEST--
secp256k1_ec_privkey_tweak_mul no coercion of classes, causes error
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKey = new stdClass;
$tweak = str_repeat("a", 32);

try {
    \secp256k1_ec_privkey_tweak_mul($context, $secKey, $tweak);
} catch (\Error $e) {
    echo get_class($e) . PHP_EOL;
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
TypeError
Argument 2 passed to secp256k1_ec_privkey_tweak_mul() must be of the type string, object given
--TEST--
secp256k1_ec_privkey_tweak_mul errors if invalid values are incorrect size
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$chars31 = str_repeat("A", 31);
$chars32 = str_repeat("A", 32);
$chars33 = str_repeat("A", 33);
$chars0 = "";

try {
    $result = secp256k1_ec_privkey_tweak_mul($context, $chars32, $chars33);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_privkey_tweak_mul($context, $chars32, $chars31);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_privkey_tweak_mul($context, $chars32, $chars32);
    echo $result . PHP_EOL;
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_privkey_tweak_mul($context, $chars33, $chars32);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_privkey_tweak_mul($context, $chars0, $chars32);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_privkey_tweak_mul(): Parameter 3 should be 32 bytes
secp256k1_ec_privkey_tweak_mul(): Parameter 3 should be 32 bytes
1
secp256k1_ec_privkey_tweak_mul(): Parameter 2 should be 32 bytes
secp256k1_ec_privkey_tweak_mul(): Parameter 2 should be 32 bytes

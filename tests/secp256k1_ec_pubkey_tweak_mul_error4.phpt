--TEST--
secp256k1_ec_pubkey_tweak_mul errors if tweak is incorrect size
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

$key = str_repeat("u", 32);
$pubKey = null;
$result = secp256k1_ec_pubkey_create($context, $pubKey, $key);
echo $result . PHP_EOL;

try {
    $result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $chars33);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $chars31);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
1
secp256k1_ec_pubkey_tweak_mul(): Parameter 3 should be 32 bytes
secp256k1_ec_pubkey_tweak_mul(): Parameter 3 should be 32 bytes

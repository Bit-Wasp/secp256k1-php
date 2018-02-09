--TEST--
secp256k1_ec_pubkey_create throws an exception if seckey is incorrect size
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

$pub = null;
try {
    $result = secp256k1_ec_pubkey_create($context, $pub, $chars31);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_pubkey_create($context, $pub, $chars33);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

try {
    $result = secp256k1_ec_pubkey_create($context, $pub, $chars0);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_pubkey_create(): Parameter 2 should be 32 bytes
secp256k1_ec_pubkey_create(): Parameter 2 should be 32 bytes
secp256k1_ec_pubkey_create(): Parameter 2 should be 32 bytes

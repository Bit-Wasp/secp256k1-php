--TEST--
secp256k1_ec_seckey_verify errors if key is wrong size
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$wrongSizeKey = str_repeat("A", 31);

try {
    secp256k1_ec_seckey_verify($context, $wrongSizeKey);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_seckey_verify(): Parameter 1 should be 32 bytes

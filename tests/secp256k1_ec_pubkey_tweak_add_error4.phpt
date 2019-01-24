--TEST--
secp256k1_ec_pubkey_tweak_add returns false if context wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

\set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyOne = str_repeat("\x00", 31) . "\x01";
$secKeyTwoBad = "\x02";

/** @var resource $pubKey */
$pubKey = null;
$result = secp256k1_ec_pubkey_create($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;

try {
    secp256k1_ec_pubkey_tweak_add($context, $pubKey, $secKeyTwoBad);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
1
secp256k1_ec_pubkey_tweak_add(): Parameter 3 should be 32 bytes

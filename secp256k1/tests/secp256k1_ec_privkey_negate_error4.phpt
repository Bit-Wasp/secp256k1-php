--TEST--
secp256k1_ec_privkey_negate throws exception if privKey is not 32 bytes
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = "1234abcd";
try {
    secp256k1_ec_privkey_negate($ctx, $privKey);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_privkey_negate(): Parameter 2 should be 32 bytes
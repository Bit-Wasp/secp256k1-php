--TEST--
secp256k1_ec_privkey_negate throws exception if privKey is not a string
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
declare(strict_types=1);
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = 1;
try {
    secp256k1_ec_privkey_negate($ctx, $privKey);
} catch (\TypeError $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
Argument 2 passed to secp256k1_ec_privkey_negate() must be of the type string, integer given
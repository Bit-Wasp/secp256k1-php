--TEST--
secp256k1_ec_privkey_negate throws \TypeError if privKey is not a string and strict_types=1
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (PHP_VERSION_ID < 70200) print "skip, <php7.2";
?>
--FILE--
<?php
declare(strict_types=1);
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = 1;
try {
    secp256k1_ec_privkey_negate($ctx, $privKey);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_privkey_negate(): Parameter 2 should be string
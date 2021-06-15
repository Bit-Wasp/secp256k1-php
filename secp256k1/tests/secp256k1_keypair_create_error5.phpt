--TEST--
secp256k1_keypair_create returns 0 if seckey length != 32
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_keypair_create")) print "skip no extrakeys support";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$seckey = pack("H*", "00000000000000000000000000000000000000000000000000000000000003"); // 31 chars
$keypair = null;
try {
    secp256k1_keypair_create($ctx, $keypair, $seckey);
    echo $result . PHP_EOL;
} catch (\Exception $e) {
    echo $e->getMessage().PHP_EOL;
}


?>
--EXPECT--
secp256k1_keypair_create(): Parameter 3 should be 32 bytes
--TEST--
secp256k1_ecdh - custom hash functions can be used (not 32 bytes)
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_ecdh")) print "skip no ecdh support";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x40");

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

// Function we suppose is equivalent to upstreams default hash fxn
$hashFxn = function (&$output, $x, $y) {
    $version = 0x02 | (unpack("C", $y[31])[1] & 0x01);
    $ctx = hash_init('sha384', 0);
    hash_update($ctx, pack("C", $version));
    hash_update($ctx, $x);
    $output = hash_final($ctx, true);
    return 1;
};

$secret = '';
// it's sha384, but 384 is the number of bits. divide by 8 for bytes.
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2, $hashFxn, 384/8);
echo $result . PHP_EOL;
echo unpack("H*", $secret)[1].PHP_EOL;

?>
--EXPECT--
1
1
774b629c86a6dbbcaa384bbb8a5fd34ca4c96431151a8da482865377dacc86d7638edb0f4761d0abca7853d156c4a46a

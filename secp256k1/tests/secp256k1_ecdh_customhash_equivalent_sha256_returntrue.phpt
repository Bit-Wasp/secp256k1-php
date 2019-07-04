--TEST--
secp256k1_ecdh - can write equivalent hash fxn to default. callback returns true, not 1.
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x40");
$expectedSecret = '238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec';

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

// Function we suppose is equivalent to upstreams default hash fxn
$hashFxn = function (&$output, $x, $y, $data) {
    $version = 0x02 | (unpack("C", $y[31])[1] & 0x01);
    $ctx = hash_init('sha256', 0);
    hash_update($ctx, pack("C", $version));
    hash_update($ctx, $x);
    $output = hash_final($ctx, true);
    return true;
};

$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2, $hashFxn, 32, NULL);
echo $result . PHP_EOL;
echo unpack("H*", $secret)[1].PHP_EOL;

$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2);
echo $result . PHP_EOL;
echo unpack("H*", $secret)[1].PHP_EOL;

?>
--EXPECT--
1
1
238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec
1
238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec


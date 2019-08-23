--TEST--
secp256k1_ecdh - custom hash function can typehint X / Y as string, and data can be int
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
$expectedSecret = '238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec';

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

// Function we suppose is equivalent to upstreams default hash fxn
$hashFxn = function (&$output, string $x, string $y, int $data) {
    $version = 0x02 | (unpack("C", $y[31])[1] & 0x01);
    echo "secret x: ".bin2hex($x).PHP_EOL;
    echo "secret y: ".bin2hex($y).PHP_EOL;
    echo "extra: "; var_dump($data);
    $ctx = hash_init('sha256', 0);
    hash_update($ctx, pack("C", $version));
    hash_update($ctx, $x);
    $output = hash_final($ctx, true);
    return 1;
};

$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2, $hashFxn, 256/8, 128);
echo $result . PHP_EOL;
echo unpack("H*", $secret)[1].PHP_EOL;

?>
--EXPECT--
1
secret x: 17d1ee664632a741f87da19c82d4fc8352368305062370769cf78779ad6ad250
secret y: 70d091c815ec945c61c282e60be6da41423b00b415d76e44ae58a343d670797b
extra: int(128)
1
238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec

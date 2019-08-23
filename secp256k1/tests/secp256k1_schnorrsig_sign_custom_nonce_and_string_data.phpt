--TEST--
secp256k1_schnorrsig_sign works a user provided nonce function, with additional string data
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
$privKey = str_repeat("\x90", 32);
//0262cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79

$hashFxn = function (&$nonce, string $msg,
    string $key32, $algo16, string $data, int $attempt) {
    echo "triggered callback\n";
    var_dump($data);
    $nonce = str_repeat("\x42", 32);
    return 1;
};

$msg32 = hash('sha256', "some message", true);
$sig = null;
$sigOut = '';

$result = secp256k1_schnorrsig_sign($ctx, $sig, $msg32, $privKey, $hashFxn, "ABCD");
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_serialize($ctx, $sigOut, $sig);
echo $result.PHP_EOL;

echo unpack("H*", $sigOut)[1].PHP_EOL;

?>
--EXPECT--
triggered callback
string(4) "ABCD"
1
1
24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c76badaec2bc699660d7a17f3457c5e4aeef226a5890676675cc25b7ee7a25de2
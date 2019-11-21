--TEST--
secp256k1_xonly_pubkey_from_pubkey returns false with warning if pubkey is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = str_repeat("\x42", 32);
//0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c

$badPubKey = tmpfile();
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$result = secp256k1_xonly_pubkey_from_pubkey($ctx, $xonlyPubKey, $hasSquareY, $badPubKey);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_pubkey_from_pubkey(): supplied resource is not a valid secp256k1_pubkey resource
0
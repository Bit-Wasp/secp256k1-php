--TEST--
secp256k1_xonly_pubkey_to_pubkey works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sign = 1;
$pubkey = null;
$badKey = tmpfile();

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$result = secp256k1_xonly_pubkey_to_pubkey($ctx, $pubkey, $badKey, $sign);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_pubkey_to_pubkey(): supplied resource is not a valid secp256k1_xonly_pubkey resource
0
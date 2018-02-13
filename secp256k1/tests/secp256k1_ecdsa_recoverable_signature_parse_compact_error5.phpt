--TEST--
secp256k1_ecdsa_recoverable_signature_parse_compact returns false on bad sig
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$recid = 1;
$sigIn = str_repeat("\xff", 64);
$signature = null;

$result = secp256k1_ecdsa_recoverable_signature_parse_compact($context, $signature, $sigIn, $recid);
echo $result . PHP_EOL;

?>
--EXPECT--
0
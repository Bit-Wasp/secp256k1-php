--TEST--
secp256k1_ecdsa_signature_serialize_der returns false if missing required parameters
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ecdsa_signature_serialize_der();
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_signature_serialize_der() expects exactly 3 parameters, 0 given
boolean
false

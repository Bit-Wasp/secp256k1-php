--TEST--
secp256k1_context_clone returns false if missing flags argument
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx1 = secp256k1_context_clone();
echo gettype($ctx1) . PHP_EOL;
echo ($ctx1 ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_context_clone() expects exactly 1 parameter, 0 given
boolean
false

--TEST--
secp256k1_context_create returns false if provided invalid flags
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx1 = secp256k1_context_create(SECP256K1_CONTEXT_SIGN << 2 | (SECP256K1_CONTEXT_VERIFY+2>>1));
echo gettype($ctx1) . PHP_EOL;
echo ($ctx1 ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
boolean
false
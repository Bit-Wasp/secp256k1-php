--TEST--
secp256k1_nonce_function_bipschnorr returns a result
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$output = '';
$msg32 = str_repeat('A', 32);
$key32 = str_repeat('Z', 32);
$algo = NULL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=null, $_data=null, $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=str_repeat("W", 16), $_data=null, $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=null, $_data=str_repeat("F", 32), $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

?>
--EXPECT--
1
a9be39328bdf208e8b9e3cfafe7909c9816314193139c93f2d092efa8de68703
1
c437c1fda591773cba3c9aa3a0676de698bc8abbde9b19ae6ae5163d3815e447
1
03da74950c67f923871c0052de77dd137b26943e1d4eacb573590aa82820b0a4
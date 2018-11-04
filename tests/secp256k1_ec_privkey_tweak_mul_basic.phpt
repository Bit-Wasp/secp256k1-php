--TEST--
secp256k1_ec_privkey_tweak_mul works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyZero = str_repeat("\x00", 32);
$secKeySixteen = str_repeat("\x00", 31) . "\x0f";
$secKeyTwo = str_repeat("\x00", 31) . "\x02";
$secKeyOne = str_repeat("\x00", 31) . "\x01";

$key = $secKeyTwo;
$result = secp256k1_ec_privkey_tweak_mul($context, $key, $secKeyTwo);
echo $result . PHP_EOL;
// 4
echo unpack("H*", $key)[1] . PHP_EOL;

$result = secp256k1_ec_privkey_tweak_mul($context, $key, $secKeyTwo);
echo $result . PHP_EOL;
// 8
echo unpack("H*", $key)[1] . PHP_EOL;

$result = secp256k1_ec_privkey_tweak_mul($context, $key, $secKeyTwo);
echo $result . PHP_EOL;
// 16
echo unpack("H*", $key)[1] . PHP_EOL;

?>
--EXPECT--
1
0000000000000000000000000000000000000000000000000000000000000004
1
0000000000000000000000000000000000000000000000000000000000000008
1
0000000000000000000000000000000000000000000000000000000000000010

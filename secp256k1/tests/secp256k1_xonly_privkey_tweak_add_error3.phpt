--TEST--
secp256k1_xonly_privkey_tweak_add throws if seckey is wrong length
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$tweak32 = str_repeat("\x02", 32);
$privKey1 = str_repeat("\x42", 31);
$expecting = "secp256k1_xonly_privkey_tweak_add(): Parameter 2 should be 32 bytes";

try {
    secp256k1_xonly_privkey_tweak_add($ctx, $privKey1, $tweak32);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

?>
--EXPECT--
secp256k1_xonly_privkey_tweak_add(): Parameter 2 should be 32 bytes
--TEST--
secp256k1_xonly_privkey_tweak_add throws exception if tweak32 is not 32 bytes
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$pubkey2 = null;
$tweakEmpty = "";
$tweak31 = str_repeat("A", 31);
$tweak33 = str_repeat("A", 31);

$privKey1 = str_repeat("\x42", 32);

$expecting = "secp256k1_xonly_privkey_tweak_add(): Parameter 3 should be 32 bytes";

try {
    secp256k1_xonly_privkey_tweak_add($ctx, $privKey1, $tweakEmpty);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

try {
    secp256k1_xonly_privkey_tweak_add($ctx, $privKey1, $tweak31);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

try {
    secp256k1_xonly_privkey_tweak_add($ctx, $privKey1, $tweak33);
} catch (\Exception $e) {
    if ($e->getMessage() !== $expecting) {
        echo "ERROR\n";
    }
    echo $e->getMessage() . "\n";
}

?>
--EXPECT--
secp256k1_xonly_privkey_tweak_add(): Parameter 3 should be 32 bytes
secp256k1_xonly_privkey_tweak_add(): Parameter 3 should be 32 bytes
secp256k1_xonly_privkey_tweak_add(): Parameter 3 should be 32 bytes
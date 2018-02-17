--TEST--
secp256k1_ec_privkey_negate throws \TypeError if privKey is not a string and strict_types=1
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (PHP_VERSION_ID < 70200) print "skip, <php7.2";
?>
--FILE--
<?php
declare(strict_types=1);
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = 1;
try {
    secp256k1_ec_privkey_negate($ctx, $privKey);
} catch (\TypeError $e) {
    if ("Argument 2 passed to secp256k1_ec_privkey_negate() must be of the type string, int given" === $e->getMessage()) {
        $message = str_replace("int given", "integer given", $e->getMessage());
    } else {
        $message = $e->getMessage();
    }
    echo $message . PHP_EOL;
}

?>
--EXPECT--
Argument 2 passed to secp256k1_ec_privkey_negate() must be of the type string, integer given
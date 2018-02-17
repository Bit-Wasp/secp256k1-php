--TEST--
Code coverage for PHP_MINFO_FUNCTION(secp256k1)
--SKIPIF--
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
--FILE--
<?php
ob_start();
phpinfo(INFO_MODULES);
$v = ob_get_clean();
$r = preg_match('/secp256k1 support .* enabled/', $v);
if ($r !== 1)
    var_dump($r);
echo "Done\n";
?>
--EXPECTF--
Done
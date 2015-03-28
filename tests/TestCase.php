<?php

namespace BitWasp\Secp256k1Tests;

class TestCase extends \PHPUnit_Framework_TestCase
{
    public function toBinary32($str)
    {
        return str_pad(pack("H*", (string)$str), 32, chr(0), STR_PAD_LEFT);
    }

    public function getPrivate()
    {
        do
        {
            $key = \openssl_random_pseudo_bytes(32);
        } while(secp256k1_ec_seckey_verify($key) == 0);
        return $key;
    }
}

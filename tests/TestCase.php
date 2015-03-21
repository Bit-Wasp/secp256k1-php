<?php

namespace BitWasp\Secp256k1Tests;

class TestCase extends \PHPUnit_Framework_TestCase
{
    public function toBinary32($str)
    {
        return str_pad(pack("H*", (string)$str), 32, chr(0), STR_PAD_LEFT);
    }
}

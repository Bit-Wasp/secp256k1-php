<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyVerifyTest extends TestCase
{

    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array($vector['pubkey']);
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testVerifiesPublicKey($pubkey)
    {
        $this->genericTest($pubkey, 1);
    }

    /**
     * @param $pubkey
     * @param $eVerify
     */
    private function genericTest($pubkey, $eVerify)
    {
        $pubkey = $this->toBinary32($pubkey);
        $context = $this->context();
        $this->assertEquals($eVerify, secp256k1_ec_pubkey_verify($context, $pubkey));
    }

     public function getErroneousTypeVectors()
     {
        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();

        return array(
            array($array),
            array($resource),
            array($class)
        );
     }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException PHPUnit_Framework_Error_Warning
     */
        public function testErroneousTypes($seckey)
        {
            $context = $this->context();
            $r = \secp256k1_ec_pubkey_verify($seckey);
        }
}

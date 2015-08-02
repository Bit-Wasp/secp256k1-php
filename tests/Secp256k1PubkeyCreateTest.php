<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyCreateTest extends TestCase
{
    /**
     * @return array
     */
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $context = TestCase::getContext();
        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array(
                $context,
                $vector['seckey'],
                $vector['compressed'],
                $vector['pubkey']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testCreatesPubkey($context, $hexPrivKey, $expectedCompressed, $expectedPubKey)
    {
        $this->genericTest($context, $hexPrivKey, 1, $expectedCompressed, 1);
        $this->genericTest($context, $hexPrivKey, 0, $expectedPubKey, 1);
    }

    /**
     * @param $hexPrivkey
     * @param $fcompressed
     * @param $expectedKey
     * @param $eResult
     */
    public function genericTest($context, $hexPrivkey, $fcompressed, $expectedKey, $eResult)
    {
        $secretKey = $this->toBinary32($hexPrivkey);

        $pubkey = '';
        $this->assertEquals($eResult, secp256k1_ec_pubkey_create($context, $secretKey, $pubkey));
        $this->assertEquals('secp256k1_pubkey_t', get_resource_type($pubkey));

        $serialized = '';
        secp256k1_ec_pubkey_serialize($context, $pubkey, $fcompressed, $serialized);
        $this->assertEquals($expectedKey, bin2hex($serialized));
        $this->assertEquals(($fcompressed ? 33 : 65), strlen($serialized));
    }

    public function getErroneousTypeVectors()
    {
        $context = TestCase::getContext();

        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();
        return array(
            array($context, $array),
            array($context, $resource),
            array($context, $class),
        );
    }
    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException \PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($context, $seckey)
    {
        $pubkey = '';
        \secp256k1_ec_pubkey_create($context, $seckey, $pubkey);
    }

}

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
        $this->assertEquals($eResult, secp256k1_ec_pubkey_create($context, $secretKey, $fcompressed, $pubkey));
        $this->assertEquals(bin2hex($pubkey), $expectedKey);
        $this->assertEquals(($fcompressed ? 33 : 65), strlen($pubkey));
    }


    public function getErroneousTypeVectors()
    {
        $context = TestCase::getContext();
        $compressed = 1;
        $privateKey = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $array = array();
        $class = new self;
        $resource = openssl_pkey_new();
        return array(
            array($context, $array, $compressed),
            array($context, $privateKey, $array),
            array($context, $resource, $compressed),
            array($context, $privateKey, $resource),
            array($context, $class, $compressed),
            array($context, $privateKey, $class)
        );
    }
    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException \PHPUnit_Framework_Error_Warning
     */
    public function testErroneousTypes($context, $seckey, $compressed)
    {
        $pubkey = '';
        $r = \secp256k1_ec_pubkey_create($context, $seckey, $compressed, $pubkey);
    }
    /**
     * @expectedException \PHPUnit_Framework_Error_Warning
     */
    public function testCompressedAsAString()
    {
        $privateKey = $this->pack('0af79b2b747548d59a4a765fb73a72bc4208d00b43d0606c13d332d5c284b0ef');
        $pubkey = '';
        \secp256k1_ec_pubkey_create(TestCase::getContext(), $privateKey, 'string', $pubkey);
    }
}

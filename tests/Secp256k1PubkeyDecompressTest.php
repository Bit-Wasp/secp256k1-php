<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyDecompressTest extends TestCase
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
                $vector['compressed'],
                $vector['pubkey']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testDecompressesPubkey($context, $expectedCompressed, $expectedUncompressed)
    {
        $publickey = $this->toBinary32($expectedCompressed);
        $decompressed = '';
        $result = secp256k1_ec_pubkey_decompress($context, $publickey, $decompressed);
        $this->assertEquals(1, $result, 'check for success');
        $this->assertEquals($expectedUncompressed, bin2hex($decompressed));
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
            array($context, $class)
        );
    }

    /**
     * @dataProvider getErroneousTypeVectors
     * @expectedException \Exception
     */
    public function testErroneousTypes($context, $key)
    {
        \secp256k1_ec_pubkey_decompress($context, '', $key);
    }
}

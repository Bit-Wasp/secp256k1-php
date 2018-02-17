<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyEncodingTest extends TestCase
{
    /**
     * @return array
     */
    public function getVectors()
    {
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/pubkey_create.yml'));

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
    public function testEncodingIsConsistent($context, $hexPrivKey, $expectedCompressed, $expectedPubKey)
    {
        $pkOut = null;
        $result = secp256k1_ec_pubkey_parse($context, $pkOut, hex2bin($expectedPubKey));
        $this->assertEquals(1, $result);

        $pkWrite = '';
        $result = secp256k1_ec_pubkey_serialize($context, $pkWrite, $pkOut, true);
        $this->assertEquals(1, $result);
        $this->assertEquals(hex2bin($expectedCompressed), $pkWrite);

        $pkWrite = '';
        $result = secp256k1_ec_pubkey_serialize($context, $pkWrite, $pkOut, false);
        $this->assertEquals(1, $result);
        $this->assertEquals(hex2bin($expectedPubKey), $pkWrite);
    }
}

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

        /** @var resource $pubkey */
        $pubkey = null;
        $this->assertEquals($eResult, secp256k1_ec_pubkey_create($context, $pubkey, $secretKey));
        $this->assertEquals(SECP256K1_TYPE_PUBKEY, get_resource_type($pubkey));

        $serialized = '';
        $flags = $fcompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize($context, $serialized, $pubkey, $flags);
        $this->assertEquals($expectedKey, bin2hex($serialized));
        $this->assertEquals(($fcompressed ? 33 : 65), strlen($serialized));
    }
}

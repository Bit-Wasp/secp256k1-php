<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyTweakAddTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $stop = 0;
        $parser = new Yaml();
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/secp256k1_pubkey_tweak_add.yml'));

        $compressed = 0;
        $context = TestCase::getContext();
        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            if ($stop && $c >= 2) {
                break;
            }
            $fixtures[] = array(
                $context,
                $vector['publicKey'],
                $vector['tweak'],
                $vector['tweaked'],
                $compressed
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testAddsToPubkey($context, $publicKey, $tweak, $expectedPublicKey, $compressed)
    {
        $this->genericTest(
            $context,
            $publicKey,
            $tweak,
            $expectedPublicKey,
            1,
            $compressed
        );
    }

    /**
     * @param $publicKey
     * @param $tweak
     * @param $expectedPublicKey
     * @param $eAdd
     */
    private function genericTest($context, $publicKey, $tweak, $expectedPublicKey, $eAdd, $compressed)
    {
        $publicKey = $this->toBinary32($publicKey);
        /** @var resource $p */
        $p = null;
        secp256k1_ec_pubkey_parse($context, $p, $publicKey);
        $tweak = $this->toBinary32($tweak);
        $result = secp256k1_ec_pubkey_tweak_add($context, $p, $tweak);
        $this->assertEquals($eAdd, $result);

        $pSer = '';
        $flags = $compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize($context, $pSer, $p, $flags);
        $this->assertEquals(bin2hex($pSer), $expectedPublicKey);
    }
}

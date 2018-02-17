<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PubkeyTweakMulTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $limit = 0;
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/secp256k1_pubkey_tweak_mul.yml'));

        $compressed = 0;
        $context = TestCase::getContext();
        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            if ($limit && $c >= $limit) {
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
    public function testMultipliesByPubkey($context, $publicKey, $tweak, $expectedPublicKey, $compressed)
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
     * @param $eMul
     */
    private function genericTest($context, $publicKey, $tweak, $expectedPublicKey, $eMul, $compressed)
    {
        $publicKey = $this->toBinary32($publicKey);
        $tweak = $this->toBinary32($tweak);
        /** @var resource $p */
        $p = null;
        secp256k1_ec_pubkey_parse($context, $p, $publicKey);
        $result = secp256k1_ec_pubkey_tweak_mul($context, $p, $tweak);
        $this->assertEquals($eMul, $result);
        $ser = null;
        secp256k1_ec_pubkey_serialize($context, $ser, $p, $compressed);
        $this->assertEquals($expectedPublicKey, bin2hex($ser));
    }
}

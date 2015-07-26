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
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/secp256k1_pubkey_tweak_mul.yml');

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
                $vector['tweaked']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testMultipliesByPubkey($context, $publicKey, $tweak, $expectedPublicKey)
    {
        $this->genericTest(
            $context,
            $publicKey,
            $tweak,
            $expectedPublicKey,
            1
        );
    }

    /**
     * @param $publicKey
     * @param $tweak
     * @param $expectedPublicKey
     * @param $eMul
     */
    private function genericTest($context, $publicKey, $tweak, $expectedPublicKey, $eMul)
    {
        $publicKey = $this->toBinary32($publicKey);
        $tweak = $this->toBinary32($tweak);
        $result = secp256k1_ec_pubkey_tweak_mul($context, $publicKey, $tweak);
        $this->assertEquals($eMul, $result);
        $this->assertEquals($expectedPublicKey, bin2hex($publicKey));
    }
}

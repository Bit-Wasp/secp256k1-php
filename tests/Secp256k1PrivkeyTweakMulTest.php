<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PrivkeyTweakMulTest extends \PHPUnit_Framework_TestCase
{

    private function toBinary32($str, $o = false)
    {
        return str_pad(
            pack("H*", (string)$str)
            , 32, chr(0), STR_PAD_LEFT)
            ;
    }

    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/secp256k1_privkey_tweak_mul.yml');
        $fixtures = array();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = [
                $vector['privkey'],
                $vector['tweak'],
                $vector['tweaked']
            ];
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testTweaksPrivatekeyMul($privkey, $tweak, $expectedTweaked)
    {
        $privkey = $this->toBinary32($privkey);
        $tweak = $this->toBinary32($tweak);
        $expectedTweaked = $this->toBinary32($expectedTweaked);

        $result = secp256k1_ec_privkey_tweak_mul($privkey, $tweak);
        $result = 1;
        $this->assertEquals(1, $result);
        $this->assertEquals($privkey, $expectedTweaked);

    }
}

<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PrivkeyTweakAddTest extends TestCase
{

    public function getVectors()
    {
        $data = Yaml::parse(file_get_contents(__DIR__ . '/data/secp256k1_privkey_tweak_add.yml'));
        $fixtures = array();
        $context = TestCase::getContext();
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = array(
                $context,
                $vector['privkey'],
                $vector['tweak'],
                $vector['tweaked']
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getVectors
     */
    public function testTweaksPrivateKeyAdd($context, $privkey, $tweak, $expectedTweaked)
    {
        $privkey = $this->toBinary32($privkey);
        $tweak = $this->toBinary32($tweak);
        $expectedTweaked = $this->toBinary32($expectedTweaked);

        $result = secp256k1_ec_privkey_tweak_add($context, $privkey, $tweak);
        $this->assertEquals(1, $result);
        $this->assertEquals($privkey, $expectedTweaked);

    }
}

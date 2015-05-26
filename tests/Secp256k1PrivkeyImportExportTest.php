<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1PrivkeyImportExportTest extends TestCase
{
    /**
     * @return array
     */
    public function getPkVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/pubkey_create.yml');

        $fixtures = array();
        foreach ($data['vectors'] as $c => $vector) {
            $fixtures[] = array(
                $vector['seckey'],
                ($c%2 == 0)
            );
        }
        return $fixtures;
    }

    /**
     * @dataProvider getPkVectors
     * @param $seckey
     * @param $compressed
     */
    public function testImportExport($seckey, $compressed)
    {
        $seckey = $this->toBinary32($seckey);
        $ctx = $this->context();
        $der = '';

        $r = secp256k1_ec_privkey_export($ctx, $seckey, $compressed, $der);
        $this->assertEquals(1, $r);

        $recovered = '';
        $r = secp256k1_ec_privkey_import($ctx, $der, $recovered);
        $this->assertEquals(1, $r);


        $this->assertEquals($seckey, $recovered);
    }
}

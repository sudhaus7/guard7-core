<?php

namespace SUDHAUS7\Guard7Core\Tests\Unit;

use InvalidArgumentException;
use SUDHAUS7\Guard7Core\Factory\KeyFactory;
use PHPUnit\Framework\TestCase;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;
use SUDHAUS7\Guard7Core\Openssl\Key;
use SUDHAUS7\Guard7Core\Tests\Mockups\Dummy;

/**
 * Class KeyFactoryTest
 *
 * @covers \SUDHAUS7\Guard7Core\Factory\KeyFactory
 * @covers \SUDHAUS7\Guard7Core\Openssl\Key
 * @package SUDHAUS7\Guard7Core\Tests\Unit
 */
class KeyFactoryTest extends TestCase
{
    protected $key='-----BEGIN PRIVATE KEY-----
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
tq7/ZVTmF+TsUFItApDXsg76kZ66oPJufw==
-----END PRIVATE KEY-----';

    public function testNewKey(): void
    {
        $key = KeyFactory::newKey(Key::class);
        $this->assertInstanceOf(CryptExtensionInterface::class, $key);
    }

    public function testWrongClass(): void
    {
        $this->expectException(InvalidArgumentException::class);
        KeyFactory::newKey(Dummy::class);
    }

    public function testReadFromFileOrData(): void
    {
        $test = KeyFactory::readFromString(Key::class, $this->key);
        $this->assertInstanceOf(CryptExtensionInterface::class, $test);
    }
    public function testReadFromFileOrDataWrongClass(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $test = KeyFactory::readFromString(Dummy::class, $this->key);
    }
}

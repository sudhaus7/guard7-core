<?php

namespace SUDHAUS7\Guard7Core\Tests\Unit;

use SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException;
use SUDHAUS7\Guard7Core\Exceptions\KeyNotUnlockedYetException;
use SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException;
use SUDHAUS7\Guard7Core\Openssl\Key;
use PHPUnit\Framework\TestCase;

/**
 * Class OpensslKeyTest
 *
 * @covers \SUDHAUS7\Guard7Core\Openssl\Key
 * @package SUDHAUS7\Guard7Core\Tests\Unit
 */
class OpensslKeyTest extends TestCase
{
    public function testCanCreateNewKey(): void
    {
        $testkey = Key::createNewKey();
        $this->assertInstanceOf(Key::class, $testkey);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $testkey->getKey());
    }

    public function testCanCreateNewKeyWithPassword(): void
    {
        $testkey = Key::createNewKey('testcase');
        $this->assertInstanceOf(Key::class, $testkey);
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $testkey->getKey());
    }

    public function testCanConstructFromKey(): void
    {
        $testkey = Key::createNewKey();
        $newkey = new Key($testkey->getKey());
        $this->assertInstanceOf(Key::class, $newkey);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $newkey->getKey());
    }

    public function testCanBeUnlocked(): void
    {
        $testkey = Key::createNewKey();
        $this->assertInstanceOf(Key::class, $testkey->unlock());
    }

    public function testPublicKeyCanBeRead(): void
    {
        $testkey = Key::createNewKey()->unlock();
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $testkey->getPublicKey());
    }

    public function testExceptionIsThrownIfKeyIsNotUnlocked(): void
    {
        $testkey = Key::createNewKey('testcase');
        $this->expectException(KeyNotUnlockedYetException::class);
        $key = new Key($testkey->getKey());
        $key->getPublicKey();
    }

    public function testExceptionIsThrownWhenUnlockingWithWrongPassword(): void
    {
        $testkey = Key::createNewKey('testcase');
        $key = Key::import($testkey->getKey());
        $this->expectException(WrongKeyPassException::class);
        $key->unlock('wrongpass');
    }

    public function testExceptionIsThrownWhenUnlockingWithNoPassword(): void
    {
        $testkey = Key::createNewKey('testcase');
        $key = Key::import($testkey->getKey());
        $this->expectException(KeyNotReadableException::class);
        $key->unlock();
    }

    public function testCanCreateFromPasswordprotectedKey(): void
    {
        $testkey = Key::createNewKey('testcase');
        $key = new Key($testkey->getKey(), 'testcase');
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $key->getPublicKey());
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $key->getKey());
    }

    public function testCanCreateFromPasswordprotectedKeyWithDelayedUnlock(): void
    {
        $testkey = Key::createNewKey('testcase');
        $key = new Key($testkey->getKey());
        $key->unlock('testcase');
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $key->getPublicKey());
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $key->getKey());
    }

    public function testKeyWithPasswordCanBeExported(): void
    {
        $testkey = Key::createNewKey('testcase');
        $newkey = $testkey->export('testcase');
        $this->assertInstanceOf(Key::class, $newkey);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $newkey->getKey());
        $newkey->lock('testcase');
        $this->assertStringStartsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----', $newkey->getKey());
    }

    public function testKeyWithoutPasswordanBeExported(): void
    {
        $testkey = Key::createNewKey();
        $newkey = $testkey->export();
        $this->assertInstanceOf(Key::class, $newkey);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $newkey->getKey());
    }



    public function testKeyCanBeImported(): void
    {
        $key = Key::createNewKey();
        $testkey = Key::import($key->getKey());
        $this->assertInstanceOf(Key::class, $testkey);
        $this->assertEquals($testkey->getKey(), $key->getKey());
    }

    public function testPublicKeysAreEqual(): void
    {
        $key = Key::createNewKey('testcase');
        $newkey = $key->export('testcase');
        $this->assertEquals($key->getPublicKey(), $newkey->getPublicKey());
    }

    /**
     * @covers \SUDHAUS7\Guard7Core\Service\ChecksumService::calculate()
     */
    public function testChecksummsFromPublicKeysAreEqual(): void
    {
        $testkey = Key::createNewKey('testcase');
        $newkey = $testkey->export('testcase');
        $this->assertEquals($newkey->checksumPublic(), $testkey->checksumPublic());
    }

    /**
     * @covers \SUDHAUS7\Guard7Core\Service\ChecksumService::calculate()
     */
    public function testChecksummsFromPrivateKeysAreEqual(): void
    {
        $testkey = Key::createNewKey('testcase');
        $this->assertEquals($testkey->checksumPrivate(), $testkey->checksumPrivate());
    }

    /*
    public function testCanNotInstantiatedWithInvalidKey() : void
    {
        $keydata = '-----BEGIN PRIVATE KEY-----
blafasel
blafasel
blafasel
blafasel
-----END PRIVATE KEY-----';
        $this->expectException(KeyNotReadableException::class);
        $tmp = new OpensslKey($keydata);

    }
    */
}

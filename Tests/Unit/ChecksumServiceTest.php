<?php

namespace SUDHAUS7\Guard7Core\Tests\Unit;

use SUDHAUS7\Guard7Core\Service\ChecksumService;
use PHPUnit\Framework\TestCase;

/**
 * Class ChecksumServiceTest
 *
 * @covers \SUDHAUS7\Guard7Core\Service\ChecksumService
 * @package SUDHAUS7\Guard7Core\Tests\Unit
 */
class ChecksumServiceTest extends TestCase
{
    protected  $testa = '
lorem ipsum vitae
lorem ipsum vitae
lorem ipsum vitae
lorem ipsum vitae
lorem ipsum vitae
';
    protected $testb = 'lorem ipsum vitaelorem ipsum vitaelorem ipsum vitaelorem ipsum vitaelorem ipsum vitae';
    public function testChecksumServicePublicKey(): void
    {
        $this->assertEquals(ChecksumService::calculate('-----BEGIN PUBLIC KEY-----'.$this->testa.'-----END PUBLIC KEY-----'),sha1($this->testb));
    }
    public function testChecksumServicePrivateKey(): void
    {
        $this->assertEquals(ChecksumService::calculate('-----BEGIN PRIVATE KEY-----'.$this->testa.'-----END PRIVATE KEY-----'),sha1(trim($this->testb)));
    }
    public function testChecksumServiceEncryptedPrivateKey(): void
    {
        $this->assertEquals(ChecksumService::calculate('-----BEGIN ENCRYPTED PRIVATE KEY-----'.$this->testa.'-----END ENCRYPTED PRIVATE KEY-----'),sha1(trim($this->testb)));
    }
}

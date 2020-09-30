<?php


namespace SUDHAUS7\Guard7Core\Interfaces;

use SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException;
use SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException;

interface CryptExtensionInterface
{
    public function __construct(string $privatekey, string $password=null, string $publickey = null);

    /**
     * This generates a new Keypair
     *
     * @param string|null $password
     * @return CryptExtensionInterface
     */
    public static function createNewKey(string $password = null): CryptExtensionInterface;


    /**
     * lock the private key
     * @param string $password
     * @return bool
     */
    public function lock(string $password): bool;

    /**
     * lock the Private key
     * @param string $password
     * @throws WrongKeyPassException
     * @throws KeyNotReadableException
     * @return CryptExtensionInterface
     */
    public function unlock(string $password = null): CryptExtensionInterface;

    /**
     * Import an encoded payload
     * @param string $data
     * @return CryptExtensionInterface
     */
    public static function import(string $data): CryptExtensionInterface;

    /**
     * export an encoded payload - this will return an object with an unencrypted Private Key
     * @param string|null $password
     * @return CryptExtensionInterface
     */
    public function export(string $password = null): CryptExtensionInterface;

    /**
     * Get the Private Key
     * @return string
     */
    public function getKey(): string;

    /**
     * Get the Public Key
     * @return string
     */
    public function getPublicKey(): string;

    /**
     * Calculate the Checksum of the current Private Key
     * @return string
     */
    public function checksumPrivate(): string;

    /**
     * Calculate the Checksum of the current Public Key
     * @return string
     */
    public function checksumPublic(): string;

    /**
     * @internal
     * @return mixed
     */
    public function getResource();
}

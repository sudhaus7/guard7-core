<?php


namespace SUDHAUS7\Guard7Core\Interfaces;

use SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException;
use SUDHAUS7\Guard7Core\Exceptions\UnlockException;

interface CryptExtensionService
{
    /**
     * @param string $method
     * @param array $publicKeys
     * @param string $payload
     * @return string
     */
    public static function encode(string $method, array $publicKeys, string $payload): string;

    /**
     * @param mixed $data
     * @param CryptExtensionInterface $key
     * @param string|null $password
     * @return mixed
     * @throws KeyNotReadableException
     * @throws UnlockException
     */
    public static function decode($data, CryptExtensionInterface $key, string $password =  null);
}

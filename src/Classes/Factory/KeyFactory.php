<?php


namespace SUDHAUS7\Guard7Core\Factory;

use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;

class KeyFactory
{

    /**
     * Generate a new Key object
     * @param string $keyclass
     * @param null $password
     * @return CryptExtensionInterface
     */
    public static function newKey(string $keyclass, $password = null): CryptExtensionInterface
    {
        if (!in_array(CryptExtensionInterface::class, \class_implements($keyclass), true)) {
            throw new \InvalidArgumentException('A class that implements '.CryptExtensionInterface::class.' must be provided', 1601036366);
        }

        return $keyclass::createNewKey($password);
    }

    /**
     * @param string $keyclass
     * @param string $pem
     * @param string|null $password
     * @return CryptExtensionInterface
     */
    public static function readFromString(string $keyclass, string $pem, string $password = null): CryptExtensionInterface
    {
        if (!in_array(CryptExtensionInterface::class, \class_implements($keyclass), true)) {
            throw new \InvalidArgumentException('A class that implements '.CryptExtensionInterface::class.' must be provided', 1601036366);
        }
        return new $keyclass($pem, $password);
    }
}

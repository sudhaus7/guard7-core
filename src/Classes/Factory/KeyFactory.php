<?php


namespace SUDHAUS7\Guard7Core\Factory;

use InvalidArgumentException;
use SUDHAUS7\Guard7Core\Interfaces\ConfigurationAdapterInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;

class KeyFactory
{

    /**
     * Generate a new Key object
     * @param ConfigurationAdapterInterface $configuration
     * @param null $password
     * @return CryptExtensionInterface
     */
    public static function newKey(ConfigurationAdapterInterface $configuration, $password = null): CryptExtensionInterface
    {
        $keyclass = '\\SUDHAUS7\\Guard7Core\\'.ucfirst(strtolower($configuration->getCryptLibrary())).'\\Key';
        if (!\class_exists($keyclass) || !in_array(CryptExtensionInterface::class, \class_implements($keyclass), true)) {
            throw new InvalidArgumentException('A class that implements '.CryptExtensionInterface::class.' must be provided', 1601036366);
        }
        /** @var CryptExtensionInterface $keyclass */
        return $keyclass::createNewKey($password, $configuration->getKeySize(), $configuration->getDefaultMethod());
    }

    /**
     * @param ConfigurationAdapterInterface $configuration
     * @param string $pem
     * @param string|null $password
     * @return CryptExtensionInterface
     */
    public static function readFromString(ConfigurationAdapterInterface $configuration, string $pem, string $password = null): CryptExtensionInterface
    {
        $keyclass = '\\SUDHAUS7\\Guard7Core\\'.ucfirst(strtolower($configuration->getCryptLibrary())).'\\Key';
        if (!\class_exists($keyclass) || !in_array(CryptExtensionInterface::class, \class_implements($keyclass), true)) {
            throw new InvalidArgumentException('A class that implements '.CryptExtensionInterface::class.' must be provided', 1601036366);
        }
        return new $keyclass($pem, $password);
    }
}

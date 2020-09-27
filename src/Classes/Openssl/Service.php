<?php


namespace SUDHAUS7\Guard7Core\Openssl;

use SUDHAUS7\Guard7Core\Exceptions\KeyNotReadableException;
use SUDHAUS7\Guard7Core\Exceptions\MissingKeyException;
use SUDHAUS7\Guard7Core\Exceptions\SealException;
use SUDHAUS7\Guard7Core\Exceptions\UnlockException;
use SUDHAUS7\Guard7Core\Exceptions\WrongKeyPassException;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionService;

class Service implements CryptExtensionService
{
    /**
     * @inheritDoc
     */
    public static function encode(string $method, array $publicKeys, string $payload): string
    {
        $signatures = array_keys($publicKeys);
        $pubkeys = array_values($publicKeys);
        $iv = \openssl_random_pseudo_bytes(32, $isSourceStrong);
        if (false === $isSourceStrong || false === $iv) {
            throw new \RuntimeException('IV generation failed');
        }
        foreach ($pubkeys as $idx => $key) {
            $pubkeys[$idx] = \openssl_get_publickey($key);
        }
    
        /** @phpstan-ignore-next-line */
        $ret = \openssl_seal($payload, $sealed, $ekeys, $pubkeys, $method, $iv);

        if (!($ret > 0)) {
            throw new SealException("Seal failed");
        }

        /** @var resource $key */
        foreach ($pubkeys as $key) {
            \openssl_free_key($key);
        }
        $envelope = [];
        foreach ($ekeys as $k => $ekey) {
            $envelope[$signatures[$k]]=base64_encode($ekey);
        }
        $b64_iv = base64_encode($iv);
        $json = json_encode($envelope);
        $b64_envelope = base64_encode((string)$json);
        $b64_data = base64_encode($sealed);
        return $method.':'.$b64_iv.':'.$b64_envelope.':'.$b64_data;
    }

    /**
     * @inheritDoc
     */
    public static function decode($data, CryptExtensionInterface $key, string $password =  null)
    {
        $privkey = $key->unlock($password)->getResource();
        list($method, $b64_iv, $b64_envkeys, $b64_secret) = explode(':', $data);


        $keyhash = $key->getPublicKey();
        $iv = base64_decode($b64_iv);
        $envkeys = json_decode(base64_decode($b64_envkeys), true);
        $envkey = base64_decode($envkeys[$keyhash]);

        if (!\openssl_open(base64_decode($b64_secret), $open, $envkey, $privkey, $method, $iv)) {
            \openssl_free_key($privkey);
            throw new UnlockException('Data not unlockable');
        }
        \openssl_free_key($privkey);

        if (strpos($open, 'json')===0) {
            $open = \json_decode(substr($open, 5), true);
        }
        if (strpos($open, 'serialize')===0) {
            $open = \unserialize(substr($open, 10), []);
        }
        return $open;
    }
}

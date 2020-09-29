<?php


namespace SUDHAUS7\Guard7Core\Openssl;

use RuntimeException;
use SUDHAUS7\Guard7Core\Exceptions\SealException;
use SUDHAUS7\Guard7Core\Exceptions\UnlockException;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionInterface;
use SUDHAUS7\Guard7Core\Interfaces\CryptExtensionService;
use function json_decode;
use function openssl_free_key;
use function openssl_get_publickey;
use function openssl_open;
use function openssl_random_pseudo_bytes;
use function openssl_seal;
use function unserialize;

class Service implements CryptExtensionService
{
    /**
     * @inheritDoc
     */
    public static function encode(string $method, array $publicKeys, string $payload): string
    {
        $signatures = array_keys($publicKeys);
        $pubkeys = array_values($publicKeys);
        $ivHash = openssl_random_pseudo_bytes(32, $isSourceStrong);
        if (false === $isSourceStrong || false === $ivHash) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException('IV generation failed');
            // @codeCoverageIgnoreEnd
        }
        foreach ($pubkeys as $idx => $key) {
            $pubkeys[$idx] = openssl_get_publickey($key);
        }

        $ret = openssl_seal($payload, $sealed, $ekeys, $pubkeys, $method, $ivHash);

        if (!($ret > 0)) {
            // @codeCoverageIgnoreStart
            throw new SealException("Seal failed");
            // @codeCoverageIgnoreEnd
        }

        /** @var resource $key */
        foreach ($pubkeys as $key) {
            openssl_free_key($key);
        }
        $envelope = [];
        foreach ($ekeys as $k => $ekey) {
            $envelope[$signatures[$k]]=base64_encode($ekey);
        }
        $b64Iv = base64_encode($ivHash);
        $json = json_encode($envelope);
        $b64Envelope = base64_encode((string)$json);
        $b64Data = base64_encode($sealed);
        return $method.':'.$b64Iv.':'.$b64Envelope.':'.$b64Data;
    }

    /**
     * @inheritDoc
     */
    public static function decode($data, CryptExtensionInterface $key, string $password =  null)
    {
        list($method, $b64Iv, $b64Envkeys, $b64Secret) = explode(':', $data);

        $keyhash = $key->checksumPublic();
        $ivHash = base64_decode($b64Iv);
        $envkeys = json_decode(base64_decode($b64Envkeys), true);
        $envkey = base64_decode($envkeys[$keyhash]);

        if (!openssl_open(base64_decode($b64Secret), $open, $envkey, $key->unlock($password)->getResource(), $method, $ivHash)) {
            // @codeCoverageIgnoreStart
            throw new UnlockException('Data not unlockable', 1601396990);
            // @codeCoverageIgnoreEnd
        }

        if (strpos($open, 'json')===0) {
            $open = json_decode(substr($open, 5), true);
        } elseif (strpos($open, 'serialized')===0) {
            $open = unserialize(substr($open, 11), []);
        }
        return $open;
    }
}

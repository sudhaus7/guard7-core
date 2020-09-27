<?php


namespace SUDHAUS7\Guard7Core\Service;

class ChecksumService
{
    /**
     * @param string $key
     * @return string
     */
    public static function calculate(string $key): string
    {
        $key = trim($key);
        $a = explode("\n", $key);
        $core = '';
        $active = false;
        foreach ($a as $line) {
            $line = trim($line);

            if ($active && ($line == '-----END PUBLIC KEY-----' || $line == '-----END PRIVATE KEY-----' || $line == '-----END RSA PRIVATE KEY-----' || $line == '-----END ENCRYPTED PRIVATE KEY-----')) {
                $active = false;
            }

            if ($active) {
                $core .= $line;
            }

            if (!$active && ($line == '-----BEGIN PUBLIC KEY-----' || $line == '-----BEGIN PRIVATE KEY-----' || $line == '-----BEGIN RSA PRIVATE KEY-----' || $line == '-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
                $active = true;
            }
        }
        return sha1($core);
    }
}

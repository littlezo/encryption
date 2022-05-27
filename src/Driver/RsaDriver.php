<?php

declare(strict_types=1);

/**
 * #logic 做事不讲究逻辑，再努力也只是重复犯错
 * ## 何为相思：不删不聊不打扰，可否具体点：曾爱过。何为遗憾：你来我往皆过客，可否具体点：再无你。
 * @version 1.0.0
 * @author @小小只^v^ <littlezov@qq.com>  littlezov@qq.com
 * @link     https://github.com/littlezo
 * @document https://github.com/littlezo/wiki
 * @license  https://github.com/littlezo/MozillaPublicLicense/blob/main/LICENSE
 *
 */

namespace Littler\Encryption\Driver;

use Littler\Encryption\Contract\AsymmetricDriverInterface;
use Littler\Encryption\Exception\DecryptException;
use Littler\Encryption\Exception\EncryptException;
use Littler\Encryption\Exception\SupportException;
use RuntimeException;

class RsaDriver implements AsymmetricDriverInterface
{
    /**
     * 私钥.
     */
    protected ?string $private_key = null;

    /**
     * 公钥.
     */
    protected ?string $public_key = null;

    /**
     * 私钥长度.
     */
    protected ?int $private_len = 0;

    /**
     * 公钥长度.
     */
    protected ?int $public_len = 0;

    /**
     * 创建一个新的加密程序实例.
     *
     * @throws RuntimeException
     */
    public function __construct(array $options = [])
    {
        $public_key  = (string) ($options['public_key'] ?? '');
        $private_key = (string) ($options['private_key'] ?? '');
        $this->setPublicKey($public_key);
        $this->setPrivateKey($private_key);
        if (! $this->private_len || ! $this->public_len) {
            throw new SupportException('给定非合法的 OpenSSLAsymmetricKey 公密或私密', 69000);
        }
    }

    /**
     * 设置一个公钥.
     *
     * @param string $public_key
     *
     * @throws \Littler\Encryption\Exception\SupportException
     */
    public function setPublicKey($public_key): self
    {
        $public_check = openssl_pkey_get_public($public_key);
        if (! $public_check) {
            throw new SupportException('OPENSSL_KEY_CREATE_ERROR', 69201);
        }
        $pkey_detail      = openssl_pkey_get_details($public_check);
        $this->public_len = $pkey_detail['bits'];
        $this->public_key = $public_key;

        return $this;
    }

    /**
     * 设置一个私人钥.
     *
     * @param string $private_key
     *
     * @throws \Littler\Encryption\Exception\SupportException
     */
    public function setPrivateKey($private_key): self
    {
        $private_check = openssl_pkey_get_private($private_key);
        if (! $private_check) {
            throw new SupportException('OPENSSL_PRIVATE_KEY_ERROR', 69301);
        }
        $pkey_detail       = openssl_pkey_get_details($private_check);
        $this->private_len = $pkey_detail['bits'];
        $this->private_key = $private_key;

        return $this;
    }

    /**
     * 获取一个公钥.
     */
    public function getPublicKey(): string
    {
        return $this->public_key;
    }

    /**
     * 获取一个私钥.
     */
    public function getPrivateKey(): string
    {
        return $this->private_key;
    }

    /**
     * 加密.
     *
     * @param mixed $value
     * @param int   $type  类型 1 公钥 2 私钥
     *
     * @throws \Littler\Encryption\Exception\EncryptException
     */
    public function encrypt($value, int $type = 1, bool $serialize = true): string
    {
        if (gettype($value) == 'array' || gettype($value) == 'object') {
            $value = json_encode($value, JSON_UNESCAPED_UNICODE + JSON_UNESCAPED_SLASHES + JSON_FORCE_OBJECT);
        }
        $encrypted = '';
        if ($type == 1) {
            $chunk_len = $this->public_len / 8 - 11;
        } else {
            $chunk_len = $this->private_len / 8 - 11;
        }
        $chunk_data = str_split((string) $value, $chunk_len);
        foreach ($chunk_data as $chunk) {
            $chunkEncrypted = '';
            if ($type == 1) {
                $encryptionOk = openssl_public_encrypt($chunk, $chunkEncrypted, $this->public_key, OPENSSL_PKCS1_PADDING);
            } else {
                $encryptionOk = openssl_private_encrypt($chunk, $chunkEncrypted, $this->private_key, OPENSSL_PKCS1_PADDING);
            }
            if ($encryptionOk === false) {
                throw new EncryptException('ENCRYPT_FAIL', 69201);
            }
            $encrypted .= $chunkEncrypted;
        }

        return self::safe_base64_encode($encrypted);
    }

    /**
     * 解密.
     *
     * @param int $type 类型 1 公钥 2 私钥
     *
     * @throws \Littler\Encryption\Exception\DecryptException
     */
    public function decrypt(string $payload, int $type = 2, bool $unserialize = true): mixed
    {
        $decrypted      = '';
        $base64_decoded = self::safe_base64_decode($payload);
        // 分段解密
        if ($type == 1) {
            $chunk_len = $this->public_len / 8;
        } else {
            $chunk_len = $this->private_len / 8;
        }
        $chunk_data = str_split($base64_decoded, $chunk_len);
        // var_dump('chunk_len', $chunk_data);

        foreach ($chunk_data as $chunk) {
            $chunkEncrypted = '';
            if ($type == 1) {
                $encryptionOk = openssl_public_decrypt($chunk, $chunkEncrypted, $this->public_key, OPENSSL_PKCS1_PADDING);
            } else {
                $encryptionOk = openssl_private_decrypt($chunk, $chunkEncrypted, $this->private_key, OPENSSL_PKCS1_PADDING);
            }
            // var_dump('encryptionOk:', $encryptionOk);
            if ($encryptionOk === false) {
                throw new DecryptException('DECRYPT_FAIL', 69301);
            }
            $decrypted .= $chunkEncrypted;
        }

        return $decrypted;
    }

    /**
     * 生成秘钥.
     */
    public static function generateKey(array $options = []): array
    {
        $cipher['digest_alg']       = $options['digest_alg'] ?? 'sha512';
        $cipher['private_key_bits'] = $options['private_key_bits'] ?? '4096';
        $cipher['private_key_type'] = $options['private_key_type'] ?? 'OPENSSL_KEYTYPE_RSA';
        $resources                  = openssl_pkey_new($cipher);
        openssl_pkey_export($resources, $private_key, null, $cipher);
        $public_key = openssl_pkey_get_details($resources);

        if (empty($private_key) || empty($public_key)) {
            throw new SupportException('OPENSSL_KEY_CREATE_ERROR', 69101);
        }

        return [
            'public_key' => $public_key['key'],
            'private_key' => $private_key,
        ];
    }

    /**
     * base64解码
     *
     * @param array|string $string
     */
    private static function safe_base64_decode($string)
    {
        return base64_decode($string);
        $base64 = str_replace(['-', '_'], ['+', '/'], $string);

        return base64_decode($base64);
    }

    /**
     * base64编码
     *
     * @param array|string $data
     */
    private static function safe_base64_encode($data)
    {
        return base64_encode($data);

        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
}

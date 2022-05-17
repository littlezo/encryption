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

namespace Littler\Encryption\Contract;

interface DriverInterface
{
    /**
     * 加密.
     *
     * @param mixed $value
     * @param int   $type  类型 1 公钥 2 私钥
     *
     * @throws \Littler\Encryption\Exception\EncryptException
     */
    public function encrypt($value, int $type = 1, bool $serialize = true): string;

    /**
     * 解密.
     *
     * @param int $type 类型 1 公钥 2 私钥
     *
     * @throws \Littler\Encryption\Exception\DecryptException
     */
    public function decrypt(string $payload, int $type = 2, bool $unserialize = true): mixed;
}

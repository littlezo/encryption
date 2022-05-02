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

interface AsymmetricDriverInterface extends DriverInterface
{
    /**
     * 生成新秘钥.
     */
    public static function generateKey(array $options = []): array;

    /**
     * 设置一个公钥.
     *
     * @param string $public_key
     *
     * @throws \Littler\Encryption\Exception\SupportException
     */
    public function setPublicKey($public_key): self;

    /**
     * 设置一个私人钥.
     *
     * @param string $private_key
     *
     * @throws \Littler\Encryption\Exception\SupportException
     */
    public function setPrivateKey($private_key): self;

    /**
     * 获取一个公钥.
     */
    public function getPublicKey(): string;

    /**
     * 获取一个私钥.
     */
    public function getPrivateKey(): string;
}

<?php

declare(strict_types=1);
/**
 *
 * #logic 做事不讲究逻辑，再努力也只是重复犯错
 * ## 何为相思：不删不聊不打扰，可否具体点：曾爱过。何为遗憾：你来我往皆过客，可否具体点：再无你。.
 *
 * @version 1.0.0
 * @author @小小只^v^ <littlezov@qq.com>  littlezov@qq.com
 * @link     https://github.com/littlezo
 * @document https://github.com/littlezo/wiki
 * @license  https://github.com/littlezo/MozillaPublicLicense/blob/main/LICENSE
 *
 */
return [
    'default' => 'rsa',
    'driver' => [
        'rsa' => [
            'class' => \Littler\Encryption\Driver\RsaDriver::class,
            'options' => [
                'public_key' => env('RSA_PUBLIC_KEY', ''),
                'private_key' => env('RSA_PRIVATE_KEY', ''),
                'digest_alg' => env('DIGEST_ALG', 'sha512'),
                'private_key_bits' => env('PRIVATE_KEY_BITS', '4096'),
                'private_key_type' => env('PRIVATE_KEY_TYPE', 'OPENSSL_KEYTYPE_RSA'),
            ],
        ],
    ],
];

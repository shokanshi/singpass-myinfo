<?php

namespace Shokanshi\SingpassMyInfo\Dtos;

use SensitiveParameter;
use Spatie\LaravelData\Attributes\Hidden;
use Spatie\LaravelData\Data;

class PrivateKeyData extends Data
{
    public function __construct(
        #[SensitiveParameter]
        public string $keyContent, // the PEM file content

        #[SensitiveParameter]
        #[Hidden]
        public ?string $passphrase
    ) {}

    /**
     * return the sha256 of key content and use it as the key id. this is crucial for key rotation
     */
    public function keyId(): string
    {
        return hash('sha256', $this->keyContent);
    }
}

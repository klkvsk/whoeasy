<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class HopResponses
{
    public function __construct(
        public ?RawResponse $nonAuth = null,
        public ?RawResponse $auth = null,
    ) {}

    public function toArray(): array
    {
        $data = [];

        if ($this->nonAuth !== null) {
            $data['nonAuth'] = $this->nonAuth->toArray();
        }

        if ($this->auth !== null) {
            $data['auth'] = $this->auth->toArray();
        }

        return $data;
    }
}

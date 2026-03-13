<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class RawResponse
{
    public function __construct(
        public string $server,
        public string $text = '',
        public ?array $json = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'server' => $this->server,
            'text' => $this->text,
        ];

        if ($this->json !== null) {
            $data['json'] = $this->json;
        }

        return $data;
    }
}

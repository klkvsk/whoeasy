<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class Nameserver
{
    public function __construct(
        public string $hostname,
        public ?string $ipv4 = null,
        public ?string $ipv6 = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'hostname' => $this->hostname,
        ];

        if ($this->ipv4 !== null) {
            $data['ipv4'] = $this->ipv4;
        }

        if ($this->ipv6 !== null) {
            $data['ipv6'] = $this->ipv6;
        }

        return $data;
    }
}

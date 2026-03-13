<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Rdap;

/**
 * Holds the raw and parsed data from an RDAP HTTP response.
 */
readonly class RdapResponse
{
    public function __construct(
        public string $server,
        public string $url,
        public int $httpCode,
        public array $json,
        public string $rawBody,
    ) {}

    /**
     * Get the RDAP object class name (e.g., "domain", "ip network", "autnum").
     */
    public function getObjectClassName(): ?string
    {
        return $this->json['objectClassName'] ?? null;
    }

    /**
     * Get the RDAP handle.
     */
    public function getHandle(): ?string
    {
        return $this->json['handle'] ?? null;
    }

    /**
     * Get the ldhName (domain name in LDH form).
     */
    public function getLdhName(): ?string
    {
        return $this->json['ldhName'] ?? null;
    }
}

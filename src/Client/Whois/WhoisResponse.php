<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Client\Whois;

/**
 * Response from a WHOIS query, including referral chain information.
 */
readonly class WhoisResponse
{
    public function __construct(
        /** The initial server queried */
        public string $server,
        /** The query string sent */
        public string $query,
        /** The final raw text response (from the last hop) */
        public string $rawText,
        /** The referral server that provided the final response, if different from initial */
        public ?string $referralServer = null,
        /** All hops: array of ['server' => string, 'response' => string] */
        public array $hops = [],
    ) {
    }

    /**
     * Get the server that actually provided the response (initial or referral).
     */
    public function getRespondingServer(): string
    {
        return $this->referralServer ?? $this->server;
    }
}

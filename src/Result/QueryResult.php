<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Exception\RetryableException;
use Klkvsk\Whoeasy\Result\Hop\RdapHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHop;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @psalm-template TInfo of AbstractInfo
 */
readonly class QueryResult
{
    /**
     * @psalm-var ProtocolResult<TInfo,WhoisHop> $whois
     * @psalm-var ProtocolResult<TInfo,RdapHop> $rdap
     */
    public function __construct(
        /** @var TInfo */
        public ?AbstractInfo $info = null,
        /** @var ProtocolResult<TInfo, WhoisHop> */
        public ?ProtocolResult $whois = null,
        /** @var ProtocolResult<TInfo, RdapHop> */
        public ?ProtocolResult $rdap = null,
    ) {}

    /**
     * Check if any hop error is retryable (network issues, rate limits).
     */
    public function hasRetryableErrors(): bool
    {
        foreach ($this->getAllErrors() as $error) {
            if ($error instanceof RetryableException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if any hop indicates the queried object does not exist.
     */
    public function isNotFound(): bool
    {
        foreach ($this->getAllErrors() as $error) {
            if ($error instanceof NotFoundException) {
                return true;
            }
        }
        return false;
    }

    /** @return \Throwable[] */
    private function getAllErrors(): array
    {
        $errors = [];
        foreach ($this->whois?->hops ?? [] as $hop) {
            if ($hop->error !== null) {
                $errors[] = $hop->error;
            }
        }
        foreach ($this->rdap?->hops ?? [] as $hop) {
            if ($hop->error !== null) {
                $errors[] = $hop->error;
            }
        }
        return $errors;
    }

    public function toArray(): array
    {
        $data = [
            'info' => $this->info?->toArray(),
        ];

        if ($this->isNotFound()) {
            $data['notFound'] = true;
        }

        if ($this->whois !== null) {
            $data['whois'] = $this->whois->toArray();
        }

        if ($this->rdap !== null) {
            $data['rdap'] = $this->rdap->toArray();
        }

        return $data;
    }
}

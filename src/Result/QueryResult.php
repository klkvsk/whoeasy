<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Exception\RetryableException;
use Klkvsk\Whoeasy\Result\Hop\RdapHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHop;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
readonly class QueryResult
{
    /**
     * @param TInfo|null $info
     * @param ProtocolResult<AbstractInfo, WhoisHop<AbstractInfo>>|null $whois
     * @param ProtocolResult<AbstractInfo, RdapHop<AbstractInfo>>|null $rdap
     */
    public function __construct(
        public ?AbstractInfo $info = null,
        public ?ProtocolResult $whois = null,
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
    public function getAllErrors(): array
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

<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

readonly class QueryOptions
{
    public const DEFAULT_MODE = QueryMode::PreferRdap;
    public const DEFAULT_TIMEOUT = 15;
    public const DEFAULT_RECURSIVE = true;
    public const DEFAULT_MAX_REFERRALS = 3;

    public function __construct(
        public QueryMode $mode = self::DEFAULT_MODE,
        public ?string $proxyUri = null,
        public int $whoisTimeout = self::DEFAULT_TIMEOUT,
        public int $rdapTimeout = self::DEFAULT_TIMEOUT,
        public bool $recursive = self::DEFAULT_RECURSIVE,
        public int $maxReferrals = self::DEFAULT_MAX_REFERRALS,
    ) {}

    /**
     * Merge this options with per-query overrides. Override fields take priority,
     * falling back to this instance's values, then hardcoded defaults.
     */
    public function merge(?self $overrides): self
    {
        return new self(
            mode: $overrides->mode ?? $this->mode,
            proxyUri: $overrides->proxyUri ?? $this->proxyUri,
            whoisTimeout: $overrides->whoisTimeout ?? $this->whoisTimeout,
            rdapTimeout: $overrides->rdapTimeout ?? $this->rdapTimeout,
            recursive: $overrides->recursive ?? $this->recursive,
            maxReferrals: $overrides->maxReferrals ?? $this->maxReferrals,
        );
    }
}

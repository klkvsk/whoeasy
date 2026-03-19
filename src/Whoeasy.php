<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Client\Whois\HttpWhoisClient;
use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use Klkvsk\Whoeasy\Exception\NotFoundException;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParserInterface;
use Klkvsk\Whoeasy\Registry\ServerInfo;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Result\Hop\RdapHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHttpHop;
use Klkvsk\Whoeasy\Result\Info\AbstractInfo;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use Klkvsk\Whoeasy\Result\ProtocolResult;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\ResultMerger;

/**
 * Unified WHOIS + RDAP query API (v2).
 *
 * Manages recursion/referral chains at the orchestrator level.
 * Clients do single requests; Whoeasy follows referrals and merges results.
 */
class Whoeasy
{
    private QueryOptions $defaultOptions;
    private ServerRegistry $registry;
    private WhoisClient $whoisClient;
    private WhoisParserInterface $whoisParser;
    private RdapParser $rdapParser;
    private ResultMerger $resultMerger;

    public static function create(?QueryOptions $defaultOptions = null): self
    {
        return new self($defaultOptions);
    }

    public function __construct(
        ?QueryOptions $defaultOptions = null,
        ?ServerRegistry $registry = null,
        ?WhoisClient $whoisClient = null,
        ?WhoisParserInterface $whoisParser = null,
        ?RdapParser $rdapParser = null,
        ?ResultMerger $resultMerger = null,
    ) {
        $this->defaultOptions = $defaultOptions ?? new QueryOptions();
        $this->registry = $registry ?? ServerRegistry::getInstance();
        $this->whoisClient = $whoisClient ?? new WhoisClient(
            timeout: $this->defaultOptions->whoisTimeout ?? QueryOptions::DEFAULT_TIMEOUT,
            proxyUri: $this->defaultOptions->proxyUri,
        );
        $this->whoisParser = $whoisParser ?? new WhoisParser();
        $this->rdapParser = $rdapParser ?? new RdapParser();
        $this->resultMerger = $resultMerger ?? new ResultMerger();
    }

    /**
     * @return QueryResult<AbstractInfo>
     */
    public function query(string $input, ?QueryOptions $options = null): QueryResult
    {
        $merged = $this->defaultOptions->merge($options);

        return match ($merged->mode) {
            QueryMode::WhoisOnly => $this->queryWhoisOnly($input, $merged),
            QueryMode::PreferWhois => $this->queryPreferWhois($input, $merged),
            QueryMode::PreferRdap => $this->queryPreferRdap($input, $merged),
            QueryMode::RdapOnly => $this->queryRdapOnly($input, $merged),
            QueryMode::Both => $this->queryBoth($input, $merged),
        };
    }

    /** @return QueryResult<DomainInfo> */
    public function domain(string $input, ?QueryOptions $options = null): QueryResult
    {
        $result = $this->query($input, $options);
        if ($result->info !== null && !$result->info instanceof DomainInfo) {
            throw new InvalidArgumentException(
                "Expected DomainInfo, got " . $result->info::class . " for: $input"
            );
        }

        return $result; // @phpstan-ignore return.type
    }

    /** @return QueryResult<IpInfo> */
    public function ip(string $input, ?QueryOptions $options = null): QueryResult
    {
        $result = $this->query($input, $options);
        if ($result->info !== null && !$result->info instanceof IpInfo) {
            throw new InvalidArgumentException(
                "Expected IpInfo, got " . $result->info::class . " for: $input"
            );
        }
        return $result; // @phpstan-ignore return.type
    }

    /** @return QueryResult<AsnInfo> */
    public function asn(string $input, ?QueryOptions $options = null): QueryResult
    {
        $result = $this->query($input, $options);
        if ($result->info !== null && !$result->info instanceof AsnInfo) {
            throw new InvalidArgumentException(
                "Expected AsnInfo, got " . $result->info::class . " for: $input"
            );
        }
        return $result; // @phpstan-ignore return.type
    }

    public function getDefaultOptions(): QueryOptions
    {
        return $this->defaultOptions;
    }

    /** @return QueryResult<AbstractInfo> */
    protected function queryWhoisOnly(string $input, QueryOptions $options): QueryResult
    {
        $whois = $this->executeWhois($input, $options);

        return new QueryResult(
            info: $whois->info,
            whois: $whois,
        );
    }

    /** @return QueryResult<AbstractInfo> */
    protected function queryRdapOnly(string $input, QueryOptions $options): QueryResult
    {
        $rdap = $this->executeRdap($input, $options);

        return new QueryResult(
            info: $rdap->info,
            rdap: $rdap,
        );
    }

    /** @return QueryResult<AbstractInfo> */
    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        $whois = $this->executeWhois($input, $options);

        // If WHOIS succeeded or result is NotFound, don't try RDAP
        if ($whois->info !== null || $this->hasNotFoundError($whois)) {
            return new QueryResult(info: $whois->info, whois: $whois);
        }

        // WHOIS failed with non-NotFound error — try RDAP as fallback
        $rdap = $this->executeRdap($input, $options);

        return new QueryResult(
            info: $rdap->info ?? $whois->info,
            whois: $whois,
            rdap: $rdap,
        );
    }

    /** @return QueryResult<AbstractInfo> */
    protected function queryPreferRdap(string $input, QueryOptions $options): QueryResult
    {
        $rdap = $this->executeRdap($input, $options);

        // If RDAP succeeded or result is NotFound, don't try WHOIS
        if ($rdap->info !== null || $this->hasNotFoundError($rdap)) {
            return new QueryResult(info: $rdap->info, rdap: $rdap);
        }

        // RDAP failed with non-NotFound error — try WHOIS as fallback
        $whois = $this->executeWhois($input, $options);

        return new QueryResult(
            info: $whois->info ?? $rdap->info,
            whois: $whois,
            rdap: $rdap,
        );
    }

    /** @return QueryResult<AbstractInfo> */
    protected function queryBoth(string $input, QueryOptions $options): QueryResult
    {
        $whois = $this->executeWhois($input, $options);

        // If WHOIS says NotFound, don't bother with RDAP
        if ($this->hasNotFoundError($whois)) {
            return new QueryResult(info: $whois->info, whois: $whois);
        }

        $rdap = $this->executeRdap($input, $options);

        // If RDAP says NotFound, return WHOIS result only
        if ($this->hasNotFoundError($rdap)) {
            return new QueryResult(info: $whois->info, whois: $whois, rdap: $rdap);
        }

        $whoisInfo = $whois->info;
        $rdapInfo = $rdap->info;

        if ($rdapInfo !== null && $whoisInfo !== null) {
            $merged = $this->resultMerger->merge($rdapInfo, $whoisInfo);
        } else {
            $merged = $rdapInfo ?? $whoisInfo;
        }

        return new QueryResult(
            info: $merged,
            whois: $whois,
            rdap: $rdap,
        );
    }

    /**
     * Check if a protocol result has a NotFoundException in any hop.
     * @param ProtocolResult<AbstractInfo> $result
     */
    private function hasNotFoundError(ProtocolResult $result): bool
    {
        foreach ($result->hops as $hop) {
            if ($hop->error instanceof NotFoundException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Execute WHOIS query chain (with optional referral following).
     * @return ProtocolResult<AbstractInfo>
     */
    private function executeWhois(string $input, QueryOptions $options): ProtocolResult
    {
        $serverInfo = $this->registry->resolve($input);

        // HTTP-based WHOIS: single hop, no recursion
        if ($serverInfo->httpUrl !== null) {
            return $this->executeHttpWhois($input, $serverInfo, $options);
        }

        if ($serverInfo->whoisServer === null) {
            $hop = new WhoisHop(
                server: '(none)',
                query: $input,
                rawText: '',
                info: null,
                error: new ClientException("No WHOIS server available for: $input"),
            );
            return new ProtocolResult(info: null, hops: [$hop]);
        }

        $hops = [];
        $currentServer = $serverInfo->whoisServer;
        $visited = [];

        for ($hopIndex = 0; $hopIndex <= $options->maxReferrals; $hopIndex++) {
            if (in_array($currentServer, $visited, true)) {
                break;
            }
            $visited[] = $currentServer;

            $rawText = null;
            $info = null;
            $error = null;

            try {
                $queryFormat = $hopIndex === 0 ? $serverInfo->queryFormat : null;
                $rawText = $this->whoisClient->query($currentServer, $input, $options->whoisTimeout, $queryFormat);
                $info = $this->whoisParser->parse($rawText, $currentServer, $serverInfo->queryType);
            } catch (\Throwable $e) {
                $error = $e;
            }

            $hops[] = new WhoisHop(
                server: $currentServer,
                query: $input,
                rawText: $rawText ?? '',
                info: $info,
                error: $error,
            );

            if (!$options->recursive) {
                break;
            }

            // Determine referral from raw response
            $referral = $rawText !== null ? WhoisParser::extractReferralServer($rawText) : null;

            if ($referral === null || in_array($referral, $visited, true)) {
                break;
            }

            $currentServer = $referral;
        }

        // Merge all hops' info (later hops take priority)
        $hopInfos = array_filter(array_map(fn(WhoisHop $h) => $h->info, $hops));
        $merged = $hopInfos !== []
            ? $this->resultMerger->mergeAll(...array_reverse($hopInfos))
            : null;

        return new ProtocolResult(info: $merged, hops: $hops);
    }

    /**
     * Execute HTTP-based WHOIS query (single hop, no recursion).
     * @return ProtocolResult<AbstractInfo>
     */
    private function executeHttpWhois(
        string $input,
        ServerInfo $serverInfo,
        QueryOptions $options,
    ): ProtocolResult {
        assert($serverInfo->httpUrl !== null);
        assert($serverInfo->httpQueryFormat !== null);

        $server = parse_url($serverInfo->httpUrl, PHP_URL_HOST) ?: $serverInfo->httpUrl;
        $rawText = null;
        $info = null;
        $error = null;

        try {
            $httpClient = new HttpWhoisClient(
                timeout: $options->whoisTimeout,
                proxyUri: $options->proxyUri,
            );
            $rawText = $httpClient->query(
                httpUrl: $serverInfo->httpUrl,
                query: $input,
                httpQueryFormat: $serverInfo->httpQueryFormat,
                scraperName: $serverInfo->httpScraper,
                timeout: $options->whoisTimeout,
            );

            try {
                $info = $this->whoisParser->parse($rawText, $server, $serverInfo->queryType);
            } catch (\Throwable $parseError) {
                $error = $parseError;
            }
        } catch (\Throwable $e) {
            $error = $e;
        }

        $hop = new WhoisHttpHop(
            server: $server,
            query: $input,
            rawText: $rawText ?? '',
            httpUrl: $serverInfo->httpUrl,
            httpQueryFormat: $serverInfo->httpQueryFormat,
            httpScraper: $serverInfo->httpScraper,
            info: $info,
            error: $error,
        );

        return new ProtocolResult(info: $info, hops: [$hop]);
    }

    /**
     * Execute RDAP query chain (with optional referral following).
     * @return ProtocolResult<AbstractInfo>
     */
    private function executeRdap(string $input, QueryOptions $options): ProtocolResult
    {
        $serverInfo = $this->registry->resolve($input);

        if ($serverInfo->rdapUrl === null) {
            $hop = new RdapHop(
                server: '(none)',
                query: $input,
                url: '',
                json: null,
                rawBody: '',
                info: null,
                error: new ClientException("No RDAP server available for: $input"),
            );
            return new ProtocolResult(info: null, hops: [$hop]);
        }

        $rdapClient = new RdapClient(
            timeout: $options->rdapTimeout,
            proxyUri: $options->proxyUri,
        );

        $hops = [];
        $currentUrl = $rdapClient->createUrl($serverInfo->rdapUrl, $input, $serverInfo->queryType);
        $visited = [];

        for ($hopIndex = 0; $hopIndex <= $options->maxReferrals; $hopIndex++) {
            if (in_array($currentUrl, $visited, true)) {
                break;
            }
            $visited[] = $currentUrl;

            $server = parse_url($currentUrl, PHP_URL_HOST) ?: $currentUrl;
            $json = null;
            $rawBody = '';
            $info = null;
            $error = null;
            $url = $currentUrl;

            try {
                $json = $rdapClient->queryUrl($currentUrl);
                $rawBody = json_encode($json, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';

                try {
                    $info = $this->rdapParser->parse($json);
                } catch (\Throwable $parseError) {
                    $error = $parseError;
                }
            } catch (\Throwable $e) {
                $error = $e;
            }

            $hops[] = new RdapHop(
                server: $server,
                query: $input,
                url: $url,
                json: $json,
                rawBody: $rawBody,
                info: $info,
                error: $error,
            );

            if (!$options->recursive) {
                break;
            }

            // RDAP referral: extract from JSON links array
            $referralUrl = $json !== null ? RdapParser::extractReferralUrl($json) : null;
            if ($referralUrl === null || in_array($referralUrl, $visited, true)) {
                break;
            }

            $currentUrl = $referralUrl;
        }

        // Merge all hops' info (later hops take priority)
        $hopInfos = array_filter(array_map(fn(RdapHop $h) => $h->info, $hops));
        $merged = $hopInfos !== []
            ? $this->resultMerger->mergeAll(...array_reverse($hopInfos))
            : null;

        return new ProtocolResult(info: $merged, hops: $hops);
    }
}

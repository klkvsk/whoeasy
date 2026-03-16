<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Exception\InvalidArgumentException;
use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\NotSupportedException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Client\Whois\HttpWhoisClient;
use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParserInterface;
use Klkvsk\Whoeasy\Registry\ServerInfo;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Result\Info\AsnInfo;
use Klkvsk\Whoeasy\Result\Info\DomainInfo;
use Klkvsk\Whoeasy\Result\Info\IpInfo;
use Klkvsk\Whoeasy\Result\Hop\RdapHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHop;
use Klkvsk\Whoeasy\Result\Hop\WhoisHttpHop;
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

    public static function create(?QueryOptions $defaultOptions = null): static
    {
        return new static($defaultOptions);
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
        return $result;
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
        return $result;
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
        return $result;
    }

    public function getDefaultOptions(): QueryOptions
    {
        return $this->defaultOptions;
    }

    protected function queryWhoisOnly(string $input, QueryOptions $options): QueryResult
    {
        $whois = $this->executeWhois($input, $options);

        if ($whois->info === null) {
            throw new ClientException("WHOIS query failed for: $input");
        }

        return new QueryResult(
            info: $whois->info,
            whois: $whois,
        );
    }

    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryWhoisOnly($input, $options);
        } catch (\Throwable) {
            return $this->queryRdapOnly($input, $options);
        }
    }

    protected function queryPreferRdap(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryRdapOnly($input, $options);
        } catch (\Throwable) {
            return $this->queryWhoisOnly($input, $options);
        }
    }

    protected function queryRdapOnly(string $input, QueryOptions $options): QueryResult
    {
        $rdap = $this->executeRdap($input, $options);

        if ($rdap->info === null) {
            throw new ClientException("RDAP query failed for: $input");
        }

        return new QueryResult(
            info: $rdap->info,
            rdap: $rdap,
        );
    }

    protected function queryBoth(string $input, QueryOptions $options): QueryResult
    {
        $whois = null;
        $rdap = null;

        try {
            $whois = $this->executeWhois($input, $options);
        } catch (\Throwable) {
        }

        try {
            $rdap = $this->executeRdap($input, $options);
        } catch (\Throwable) {
        }

        $whoisInfo = $whois?->info;
        $rdapInfo = $rdap?->info;

        if ($whoisInfo === null && $rdapInfo === null) {
            throw new ClientException("Both WHOIS and RDAP queries failed for: $input");
        }

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
     * Execute WHOIS query chain (with optional referral following).
     */
    private function executeWhois(string $input, QueryOptions $options): ProtocolResult
    {
        $serverInfo = $this->registry->resolve($input);

        // HTTP-based WHOIS: single hop, no recursion
        if ($serverInfo->hasHttpWhois()) {
            return $this->executeHttpWhois($input, $serverInfo, $options);
        }

        if (!$serverInfo->hasWhois()) {
            throw new ClientException("No WHOIS server available for: $input");
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
            $referralServer = null;
            $error = null;

            try {
                $queryFormat = $hopIndex === 0 ? $serverInfo->queryFormat : null;
                $rawText = $this->whoisClient->query($currentServer, $input, $options->whoisTimeout, $queryFormat);

                // Strip boilerplate before detection (legal text causes false positives)
                $strippedText = WhoisClient::stripBoilerplate($rawText);

                // Detect rate limiting / not found / not supported
                if (WhoisClient::isRateLimited($strippedText)) {
                    $error = new RateLimitException("WHOIS rate limit on $currentServer");
                } elseif (WhoisClient::isNotSupported($strippedText)) {
                    $error = (new NotSupportedException("WHOIS not supported on $currentServer"))
                        ->withServer($currentServer)
                        ->withQuery($input)
                        ->withRawBody($rawText);
                } elseif (WhoisClient::isNotFound($strippedText)) {
                    $error = new NotFoundException("WHOIS: not found on $currentServer");
                }

                // Parse even if rate-limited/not-found (might still have partial data)
                try {
                    $parserResult = $this->whoisParser->parse($rawText, $currentServer, $serverInfo->queryType);
                    $info = $parserResult->info;
                    $referralServer = $parserResult->referralServer;
                } catch (\Throwable $parseError) {
                    $error ??= $parseError;
                }
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

            // Determine referral: parsed field first, regex fallback
            $referral = $referralServer;
            if ($referral === null && $rawText !== null) {
                $referral = WhoisClient::detectReferral($rawText);
            }

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
     */
    private function executeHttpWhois(
        string $input,
        ServerInfo $serverInfo,
        QueryOptions $options,
    ): ProtocolResult {
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
                $parserResult = $this->whoisParser->parse($rawText, $server, $serverInfo->queryType);
                $info = $parserResult->info;
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
     */
    private function executeRdap(string $input, QueryOptions $options): ProtocolResult
    {
        $serverInfo = $this->registry->resolve($input);

        if (!$serverInfo->hasRdap()) {
            throw new ClientException("No RDAP server available for: $input");
        }

        $rdapClient = new RdapClient(
            timeout: $options->rdapTimeout,
            proxyUri: $options->proxyUri,
        );

        $hops = [];
        $currentUrl = $serverInfo->rdapUrl;
        $visited = [];
        $isFirstHop = true;

        for ($hopIndex = 0; $hopIndex <= $options->maxReferrals; $hopIndex++) {
            if (in_array($currentUrl, $visited, true)) {
                break;
            }
            $visited[] = $currentUrl;

            $server = parse_url($currentUrl, PHP_URL_HOST) ?: $currentUrl;
            $json = null;
            $rawBody = '';
            $info = null;
            $referralServer = null;
            $error = null;
            $url = $currentUrl;

            try {
                if ($isFirstHop) {
                    $json = $rdapClient->query($currentUrl, $input, $serverInfo->queryType);
                    $isFirstHop = false;
                } else {
                    $json = $rdapClient->queryUrl($currentUrl);
                }
                $rawBody = json_encode($json, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';

                try {
                    $parserResult = $this->rdapParser->parse($json, $serverInfo->queryType);
                    $info = $parserResult->info;
                    $referralServer = $parserResult->referralServer;
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

            // RDAP referral: parsed referralServer is a full URL
            if ($referralServer === null || in_array($referralServer, $visited, true)) {
                break;
            }

            $currentUrl = $referralServer;
        }

        // Merge all hops' info (later hops take priority)
        $hopInfos = array_filter(array_map(fn(RdapHop $h) => $h->info, $hops));
        $merged = $hopInfos !== []
            ? $this->resultMerger->mergeAll(...array_reverse($hopInfos))
            : null;

        return new ProtocolResult(info: $merged, hops: $hops);
    }
}

<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Parser\Rdap\RdapParser;

use Klkvsk\Whoeasy\Client\Whois\HttpWhoisClient;
use Klkvsk\Whoeasy\Client\Whois\WhoisClient;
use Klkvsk\Whoeasy\Client\Whois\WhoisResponse;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParserInterface;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\RawResponse;
use Klkvsk\Whoeasy\Result\ResultMerger;

/**
 * Unified WHOIS + RDAP query API (v2).
 *
 * Uses new v2 components directly:
 * - ServerRegistry for server lookup
 * - WhoisClient for TCP:43 queries
 * - WhoisParser for universal WHOIS text parsing
 * - RdapClient + RdapParser for RDAP queries
 * - ResultMerger for combining results
 */
class Whoeasy
{
    private Config $config;
    private ServerRegistry $registry;
    private WhoisClient $whoisClient;
    private WhoisParserInterface $whoisParser;
    private ResultMerger $resultMerger;

    public static function create(?Config $config = null): static
    {
        return new static($config ?? new Config());
    }

    public function __construct(
        ?Config $config = null,
        ?ServerRegistry $registry = null,
        ?WhoisClient $whoisClient = null,
        ?WhoisParserInterface $whoisParser = null,
        ?ResultMerger $resultMerger = null,
    ) {
        $this->config = $config ?? new Config();
        $this->registry = $registry ?? ServerRegistry::getInstance();
        $this->whoisClient = $whoisClient ?? new WhoisClient(
            timeout: $this->config->whoisTimeout,
            proxyUri: $this->config->proxyUri,
        );
        $this->whoisParser = $whoisParser ?? new WhoisParser();
        $this->resultMerger = $resultMerger ?? new ResultMerger();
    }

    public function query(string $input, ?QueryOptions $options = null): QueryResult
    {
        $options ??= new QueryOptions();
        $mode = $options->mode ?? $this->config->defaultMode;

        return match ($mode) {
            QueryMode::WhoisOnly => $this->queryWhoisOnly($input, $options),
            QueryMode::PreferWhois => $this->queryPreferWhois($input, $options),
            QueryMode::PreferRdap => $this->queryPreferRdap($input, $options),
            QueryMode::RdapOnly => $this->queryRdapOnly($input, $options),
            QueryMode::Both => $this->queryBoth($input, $options),
        };
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    protected function queryWhoisOnly(string $input, QueryOptions $options): QueryResult
    {
        $serverInfo = $this->registry->resolve($input);
        $timeout = $options->timeout ?? $this->config->whoisTimeout;

        if ($serverInfo->hasHttpWhois()) {
            // HTTP-based WHOIS endpoint
            $httpClient = new HttpWhoisClient(
                timeout: $timeout,
                proxyUri: $options->proxyUri ?? $this->config->proxyUri,
            );
            $response = $httpClient->query(
                httpUrl: $serverInfo->httpUrl,
                query: $input,
                httpQueryFormat: $serverInfo->httpQueryFormat,
                scraperName: $serverInfo->httpScraper,
                timeout: $timeout,
            );
        } elseif ($serverInfo->hasWhois()) {
            // Standard TCP:43 WHOIS
            $response = $this->whoisClient->queryWithReferrals(
                $serverInfo->whoisServer,
                $input,
                timeout: $timeout,
                queryFormat: $serverInfo->queryFormat,
            );
        } else {
            throw new ClientException("No WHOIS server available for: $input");
        }

        $structured = $this->whoisParser->parse(
            $response->rawText,
            $response->getRespondingServer(),
            $serverInfo->queryType,
        );

        return new QueryResult(
            query: $input,
            result: $structured,
            whoisHops: [
                new RawResponse(
                    server: $response->getRespondingServer(),
                    text: $response->rawText,
                ),
            ],
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
        $serverInfo = $this->registry->resolve($input);

        if (!$serverInfo->hasRdap()) {
            throw new ClientException("No RDAP server available for: $input");
        }

        $rdapClient = new RdapClient(
            timeout: $options->timeout ?? $this->config->rdapTimeout,
            proxyUri: $options->proxyUri ?? $this->config->proxyUri,
        );

        $rdapResponse = $rdapClient->query($serverInfo->rdapUrl, $input, $serverInfo->queryType);
        $parser = new RdapParser();
        $structured = $parser->parse($rdapResponse->json, $serverInfo->queryType);

        return new QueryResult(
            query: $input,
            result: $structured,
            rdapHops: [
                new RawResponse(
                    server: $rdapResponse->server,
                    text: $rdapResponse->rawBody,
                    json: $rdapResponse->json,
                ),
            ],
        );
    }

    protected function queryBoth(string $input, QueryOptions $options): QueryResult
    {
        $whoisResult = null;
        $whoisHops = [];
        $rdapResult = null;
        $rdapHops = [];

        // Try WHOIS
        try {
            $whoisQr = $this->queryWhoisOnly($input, $options);
            $whoisResult = $whoisQr->result;
            $whoisHops = $whoisQr->whoisHops;
        } catch (\Throwable) {
            // WHOIS failed, continue
        }

        // Try RDAP
        try {
            $rdapQr = $this->queryRdapOnly($input, $options);
            $rdapResult = $rdapQr->result;
            $rdapHops = $rdapQr->rdapHops;
        } catch (\Throwable) {
            // RDAP failed, continue
        }

        if ($whoisResult === null && $rdapResult === null) {
            throw new ClientException("Both WHOIS and RDAP queries failed for: $input");
        }

        if ($rdapResult !== null && $whoisResult !== null) {
            $merged = $this->resultMerger->merge($rdapResult, $whoisResult);
        } else {
            $merged = $rdapResult ?? $whoisResult;
        }

        return new QueryResult(
            query: $input,
            result: $merged,
            rdapHops: $rdapHops,
            whoisHops: $whoisHops,
        );
    }

}

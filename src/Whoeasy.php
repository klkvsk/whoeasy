<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Client\Rdap\RdapParser;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Client\WhoisClient;
use Klkvsk\Whoeasy\Client\WhoisResponse;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\Enum\QueryType;
use Klkvsk\Whoeasy\Exception\WhoeasyException;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParser;
use Klkvsk\Whoeasy\Parser\Whois\WhoisParserInterface;
use Klkvsk\Whoeasy\Registry\ServerRegistry;
use Klkvsk\Whoeasy\Result\HopResponses;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\RawResponse;
use Klkvsk\Whoeasy\Result\ResultMerger;
use Klkvsk\Whoeasy\Result\StructuredResult;

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

        if (!$serverInfo->hasWhois()) {
            throw new WhoeasyException(
                "No WHOIS server available for: $input",
                query: $input,
            );
        }

        $timeout = $options->timeout ?? $this->config->whoisTimeout;
        $response = $this->whoisClient->queryWithReferrals(
            $serverInfo->whoisServer,
            $input,
            timeout: $timeout,
        );

        $structured = $this->whoisParser->parse(
            $response->rawText,
            $response->getRespondingServer(),
            $serverInfo->queryType,
        );

        return new QueryResult(
            query: $input,
            result: $structured,
            whois: new HopResponses(
                auth: new RawResponse(
                    server: $response->getRespondingServer(),
                    text: $response->rawText,
                ),
            ),
        );
    }

    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryWhoisOnly($input, $options);
        } catch (WhoeasyException | \Throwable) {
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
            throw new WhoeasyException(
                "No RDAP server available for: $input",
                query: $input,
            );
        }

        $rdapClient = new RdapClient(
            timeout: $options->timeout ?? $this->config->rdapTimeout,
            proxyUri: $options->proxyUri ?? $this->config->proxyUri,
        );

        $rdapResponse = $this->executeRdapQuery($rdapClient, $input, $serverInfo->queryType);
        $parser = new RdapParser();
        $intermediateResult = $parser->parse($rdapResponse);

        // Map intermediate result to StructuredResult
        $mapper = new \Klkvsk\Whoeasy\Result\ResultMapper();
        $queryTypeStr = match ($serverInfo->queryType) {
            QueryType::Domain => 'domain',
            QueryType::Ipv4 => 'ipv4',
            QueryType::Ipv6 => 'ipv6',
            QueryType::Asn => 'asn',
        };
        $structured = $mapper->mapRdapResponse($rdapResponse, $queryTypeStr);

        return new QueryResult(
            query: $input,
            result: $structured,
            rdap: new HopResponses(
                auth: new RawResponse(
                    server: $rdapResponse->server,
                    text: $rdapResponse->rawBody,
                    json: $rdapResponse->json,
                ),
            ),
        );
    }

    protected function queryBoth(string $input, QueryOptions $options): QueryResult
    {
        $whoisResult = null;
        $whoisRaw = null;
        $rdapResult = null;
        $rdapRaw = null;

        // Try WHOIS
        try {
            $whoisQr = $this->queryWhoisOnly($input, $options);
            $whoisResult = $whoisQr->result;
            $whoisRaw = $whoisQr->whois;
        } catch (\Throwable) {
            // WHOIS failed, continue
        }

        // Try RDAP
        try {
            $rdapQr = $this->queryRdapOnly($input, $options);
            $rdapResult = $rdapQr->result;
            $rdapRaw = $rdapQr->rdap;
        } catch (\Throwable) {
            // RDAP failed, continue
        }

        if ($whoisResult === null && $rdapResult === null) {
            throw new WhoeasyException(
                "Both WHOIS and RDAP queries failed for: $input",
                query: $input,
            );
        }

        if ($rdapResult !== null && $whoisResult !== null) {
            $merged = $this->resultMerger->merge($rdapResult, $whoisResult);
        } else {
            $merged = $rdapResult ?? $whoisResult;
        }

        return new QueryResult(
            query: $input,
            result: $merged,
            rdap: $rdapRaw,
            whois: $whoisRaw,
        );
    }

    private function executeRdapQuery(RdapClient $client, string $input, QueryType $queryType): RdapResponse
    {
        return match ($queryType) {
            QueryType::Domain => $client->queryDomain($input),
            QueryType::Ipv4, QueryType::Ipv6 => $client->queryIp($input),
            QueryType::Asn => $client->queryAsn(
                (int)preg_replace('/^AS/i', '', $input)
            ),
        };
    }
}

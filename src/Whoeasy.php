<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\Result\HopResponses;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\ResultMapper;
use Klkvsk\Whoeasy\Result\ResultMerger;

class Whoeasy
{
    protected Config $config;
    protected ResultMapper $resultMapper;
    protected ResultMerger $resultMerger;

    public static function create(?Config $config = null): static
    {
        return new static($config ?? new Config());
    }

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? new Config();
        $this->resultMapper = new ResultMapper();
        $this->resultMerger = new ResultMerger();
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
        // TODO: Phase C/D/E - implement with new WhoisClient + WhoisParser
        throw new \LogicException('WHOIS client not yet implemented in v2');
    }

    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryWhoisOnly($input, $options);
        } catch (\LogicException) {
            return $this->queryRdapOnly($input, $options);
        } catch (ClientException) {
            return $this->queryRdapOnly($input, $options);
        }
    }

    protected function queryPreferRdap(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryRdapOnly($input, $options);
        } catch (ClientException) {
            return $this->queryWhoisOnly($input, $options);
        }
    }

    protected function queryRdapOnly(string $input, QueryOptions $options): QueryResult
    {
        $rdapResponse = $this->executeRdapQuery($input, $options);
        $queryType = RdapClient::guessQueryType($input);
        $rawResponse = $this->resultMapper->mapRdapRawResponse($rdapResponse);
        $structured = $this->resultMapper->mapRdapResponse($rdapResponse, $queryType);

        return new QueryResult(
            query: $input,
            result: $structured,
            rdap: new HopResponses(auth: $rawResponse),
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
            return $this->queryWhoisOnly($input, $options);
        } catch (\LogicException | ClientException) {
            // WHOIS not implemented yet or failed
        }

        // Try RDAP
        try {
            $queryType = RdapClient::guessQueryType($input);
            $rdapResponse = $this->executeRdapQuery($input, $options);
            $rdapRaw = new HopResponses(auth: $this->resultMapper->mapRdapRawResponse($rdapResponse));
            $rdapResult = $this->resultMapper->mapRdapResponse($rdapResponse, $queryType);
        } catch (ClientException) {
            // RDAP failed
        }

        if ($rdapResult === null && $whoisResult === null) {
            throw new ClientException('Both WHOIS and RDAP queries failed for: ' . $input);
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

    protected function executeRdapQuery(string $input, QueryOptions $options): RdapResponse
    {
        $client = new RdapClient(
            timeout: $this->resolveTimeout($options, 'rdap'),
            proxyUri: $this->resolveProxy($options),
        );

        $queryType = RdapClient::guessQueryType($input);

        return match ($queryType) {
            RequestInterface::QUERY_TYPE_DOMAIN => $client->queryDomain($input),
            RequestInterface::QUERY_TYPE_IPV4,
            RequestInterface::QUERY_TYPE_IPV6 => $client->queryIp($input),
            RequestInterface::QUERY_TYPE_ASN => $client->queryAsn(
                (int) preg_replace('/^AS/i', '', $input)
            ),
            default => $client->queryDomain($input),
        };
    }

    protected function resolveTimeout(?QueryOptions $options, string $protocol): int
    {
        if ($options?->timeout !== null) {
            return $options->timeout;
        }

        return match ($protocol) {
            'whois' => $this->config->whoisTimeout,
            'rdap' => $this->config->rdapTimeout,
            default => 30,
        };
    }

    protected function resolveProxy(?QueryOptions $options): ?string
    {
        return $options?->proxyUri ?? $this->config->proxyUri;
    }
}

<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Rdap\RdapClient;
use Klkvsk\Whoeasy\Client\Rdap\RdapResponse;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\WhoisClient;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\Exception\UnsupportedQueryException;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\WhoisParser;
use Klkvsk\Whoeasy\Result\HopResponses;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\ResultMapper;
use Klkvsk\Whoeasy\Result\ResultMerger;

class Whoeasy
{
    protected Config $config;
    protected Whois $whois;
    protected ResultMapper $resultMapper;
    protected ResultMerger $resultMerger;

    public static function create(?Config $config = null): static
    {
        return new static($config ?? new Config());
    }

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? new Config();
        $this->whois = new Whois();
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

    /**
     * Query using WHOIS protocol only.
     */
    protected function queryWhoisOnly(string $input, QueryOptions $options): QueryResult
    {
        $answer = $this->executeWhoisQuery($input, $options);
        $rawResponse = $this->resultMapper->mapRawResponse($answer);
        $structured = $this->resultMapper->mapWhoisAnswer($answer);

        return new QueryResult(
            query: $input,
            result: $structured,
            whois: new HopResponses(auth: $rawResponse),
        );
    }

    /**
     * Query using WHOIS first; fall back to RDAP on failure.
     */
    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryWhoisOnly($input, $options);
        } catch (ClientException) {
            return $this->queryRdapOnly($input, $options);
        }
    }

    /**
     * Query using RDAP first; fall back to WHOIS on failure.
     */
    protected function queryPreferRdap(string $input, QueryOptions $options): QueryResult
    {
        try {
            return $this->queryRdapOnly($input, $options);
        } catch (ClientException) {
            return $this->queryWhoisOnly($input, $options);
        }
    }

    /**
     * Query using RDAP protocol only.
     */
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

    /**
     * Query using both WHOIS and RDAP, then merge results.
     * Both protocols are attempted; if one fails, the other's result is used alone.
     */
    protected function queryBoth(string $input, QueryOptions $options): QueryResult
    {
        $whoisResult = null;
        $whoisRaw = null;
        $rdapResult = null;
        $rdapRaw = null;

        // Try WHOIS
        try {
            $answer = $this->executeWhoisQuery($input, $options);
            $whoisRaw = new HopResponses(auth: $this->resultMapper->mapRawResponse($answer));
            $whoisResult = $this->resultMapper->mapWhoisAnswer($answer);
        } catch (ClientException) {
            // WHOIS failed, continue with RDAP only
        }

        // Try RDAP
        try {
            $queryType = RdapClient::guessQueryType($input);
            $rdapResponse = $this->executeRdapQuery($input, $options);
            $rdapRaw = new HopResponses(auth: $this->resultMapper->mapRdapRawResponse($rdapResponse));
            $rdapResult = $this->resultMapper->mapRdapResponse($rdapResponse, $queryType);
        } catch (ClientException) {
            // RDAP failed, continue with WHOIS only
        }

        // At least one must succeed
        if ($whoisResult === null && $rdapResult === null) {
            throw new ClientException('Both WHOIS and RDAP queries failed for: ' . $input);
        }

        // Merge results if both available, otherwise use whichever succeeded
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

    /**
     * Execute a WHOIS query and return the parsed answer.
     *
     * @throws ClientException
     */
    protected function executeWhoisQuery(string $input, QueryOptions $options): WhoisAnswer
    {
        $client = $this->whois->createClient();

        $timeout = $options->timeout ?? $this->config->whoisTimeout;
        $client->setTimeout($timeout);

        $proxyUri = $options->proxyUri ?? $this->config->proxyUri;

        $request = $client->createRequest($input, proxy: $proxyUri);
        $response = $client->handle($request);

        $answer = new WhoisAnswer(
            $response->getAnswer(),
            $request->getQuery(),
            $request->getQueryType(),
            $request->getServer()->getName(),
        );

        $this->whois->createParser()->parse($answer);

        return $answer;
    }

    /**
     * Execute an RDAP query and return the response.
     *
     * @throws ClientException
     */
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

    /**
     * Resolve effective mode for a query, applying defaults from config.
     */
    protected function resolveMode(?QueryOptions $options): QueryMode
    {
        return $options?->mode ?? $this->config->defaultMode;
    }

    /**
     * Resolve effective timeout for a given protocol.
     */
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

    /**
     * Resolve effective proxy URI.
     */
    protected function resolveProxy(?QueryOptions $options): ?string
    {
        return $options?->proxyUri ?? $this->config->proxyUri;
    }
}

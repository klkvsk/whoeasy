<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\WhoisClient;
use Klkvsk\Whoeasy\Enum\QueryMode;
use Klkvsk\Whoeasy\Exception\UnsupportedQueryException;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\WhoisParser;
use Klkvsk\Whoeasy\Result\HopResponses;
use Klkvsk\Whoeasy\Result\QueryResult;
use Klkvsk\Whoeasy\Result\ResultMapper;

class Whoeasy
{
    protected Config $config;
    protected Whois $whois;
    protected ResultMapper $resultMapper;

    public static function create(?Config $config = null): static
    {
        return new static($config ?? new Config());
    }

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? new Config();
        $this->whois = new Whois();
        $this->resultMapper = new ResultMapper();
    }

    public function query(string $input, ?QueryOptions $options = null): QueryResult
    {
        $options ??= new QueryOptions();
        $mode = $options->mode ?? $this->config->defaultMode;

        return match ($mode) {
            QueryMode::WhoisOnly => $this->queryWhoisOnly($input, $options),
            QueryMode::PreferWhois => $this->queryPreferWhois($input, $options),
            QueryMode::PreferRdap => $this->queryPreferRdap($input, $options),
            QueryMode::RdapOnly => throw new UnsupportedQueryException(
                'RDAP-only mode is not yet implemented. Use WhoisOnly or PreferWhois mode.'
            ),
            QueryMode::Both => throw new UnsupportedQueryException(
                'Both mode is not yet implemented. Use WhoisOnly or PreferWhois mode.'
            ),
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
     * Query using WHOIS first; RDAP fallback is not yet available.
     */
    protected function queryPreferWhois(string $input, QueryOptions $options): QueryResult
    {
        return $this->queryWhoisOnly($input, $options);
    }

    /**
     * Query using RDAP first; falls back to WHOIS since RDAP is not fully implemented.
     */
    protected function queryPreferRdap(string $input, QueryOptions $options): QueryResult
    {
        // RDAP not yet implemented - fall back to WHOIS
        return $this->queryWhoisOnly($input, $options);
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

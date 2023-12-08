<?php

namespace Klkvsk\Whoeasy\Client;

use Klkvsk\Whoeasy\Client\Adapter\AdapterInterface;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Client\Registry\ServerRegistryInterface;

class WhoisClient
{
    protected float $timeout = Request::DEFAULT_TIMEOUT;

    public function __construct(
        /** @var AdapterInterface[] */
        protected array                   $adapters,
        protected ServerRegistryInterface $registry,
    )
    {

    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $timeout): WhoisClient
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @throws ClientException
     */
    public function lookup(
        string                     $query,
        string|ServerInfoInterface &$server = null,
        string                     &$queryType = null,
    ): string
    {
        $queryType ??= Request::guessQueryType($query);

        if (!$server) {
            $server = $this->registry->findByQuery($query, $queryType)
                ?? throw new ClientException("No server in registry matching query: $query ($queryType)");
        }

        if (is_string($server)) {
            $serverName = $server;
            $server = $this->registry->findServer($serverName);
            if (!$server) {
                $serverAddress = $serverName;
                if (!str_contains($serverAddress, '://')) {
                    $serverAddress = 'whois://' . $serverAddress;
                }
                $server = new ServerInfo($serverAddress);
            }
        }

        $request = $this->createRequest($server, $query, $queryType);
        $response = $this->handle($request);

        try {
            if (empty($response->getAnswer())) {
                throw new ClientResponseException('Got empty response from server');
            }

            if (preg_match('/^clos(ing|ed) connection.*$/im', $response->getAnswer(), $m)) {
                throw new ClientResponseException($m[0]);
            }

            $rawData = $response->getAnswer();
            if ($server->getCharset()) {
                $rawData = mb_convert_encoding($rawData, 'UTF-8', $server->getCharset());
            }

            foreach ($this->getRateLimitPatterns() as $pattern) {
                if (preg_match($pattern, $rawData)) {
                    throw new RateLimitException("Rate limit exceeded for {$server->getName()}");
                }
            }

            foreach ($this->getNotFoundPatterns() as $pattern) {
                if (preg_match($pattern, $rawData)) {
                    throw new NotFoundException("Nothing found by query '$query'");
                }
            }
        } catch (ClientRequestException|ClientResponseException $e) {
            $e->withRequest($request);
            if ($e instanceof ClientResponseException) {
                $e->withResponse($response);
            }
            throw $e;
        }

        return $rawData;
    }

    protected function createRequest(ServerInfoInterface $server, string $query, string $queryType): RequestInterface
    {
        return new Request($server, $query, $queryType, $this->timeout);
    }

    public function handle(RequestInterface $request): ResponseInterface
    {
        $adapter = $this->chooseAdapter($request);

        return $adapter->handle($request);
    }

    protected function chooseAdapter(RequestInterface $request): AdapterInterface
    {
        foreach ($this->adapters as $adapter) {
            if ($adapter->canHandle($request)) {
                return $adapter;
            }
        }

        throw new ClientException("Could not find adapter for {$request->getServer()->getUri()}");
    }

    protected function getRateLimitPatterns(): array
    {
        return [
            '/exceeded the maximum allowable/im',
            '/exceeded your query limit/im',
            '/quota exceeded/i',
            '/try again after/i',
            '/rate limit exceeded/i',
        ];
    }

    protected function getNotFoundPatterns(): array
    {
        return [
            '/^no match/im',
            '/^% no match/im',
            '/^no data found/im',
            '/^%% not found/im',
            '/is available for registration/i',
            '/^status: (free|available)/mi',
            '/no matching objects found/i',
            '/(objects?|domains?|records?|entry|entries) not found/im',
            '/no (matching )?(objects?|domains?|records?|entry|entries) found/i',
            '/object does not exist/i',
            '/rate limit exceeded/i',
        ];
    }

}
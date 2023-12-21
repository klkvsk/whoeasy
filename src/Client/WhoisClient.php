<?php

namespace Klkvsk\Whoeasy\Client;

use Klkvsk\Whoeasy\Client\Adapter\AdapterInterface;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\ClientResponseException;
use Klkvsk\Whoeasy\Client\Exception\NotFoundException;
use Klkvsk\Whoeasy\Client\Exception\RateLimitException;
use Klkvsk\Whoeasy\Client\Proxy\Proxy;
use Klkvsk\Whoeasy\Client\Proxy\ProxyInterface;
use Klkvsk\Whoeasy\Client\Registry\ServerRegistryInterface;
use Klkvsk\Whoeasy\Parser\Process\CleanComments;

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

    public function createRequest(
        string $query,
        string $queryType = null,
        ServerInfoInterface|string $server = null,
        ProxyInterface|string $proxy = null
    ): RequestInterface
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


        $request = new Request($server, $query, $queryType, $this->timeout);

        if (is_string($proxy)) {
            $proxy = Proxy::fromUri($proxy);
        }
        if ($proxy) {
            $request->setProxy($proxy);
        }

        return $request;
    }

    public function handle(RequestInterface $request): ResponseInterface
    {
        $adapter = $this->chooseAdapter($request);
        $response = $adapter->handle($request);

        try {
            if (empty($response->getAnswer())) {
                throw new ClientResponseException('Got empty response from server');
            }

            if (preg_match('/^clos(ing|ed) connection.*$/im', $response->getAnswer(), $m)) {
                throw new ClientResponseException($m[0]);
            }

            $rawData = $response->getAnswer();
            if ($request->getServer()->getCharset()) {
                $rawData = mb_convert_encoding($rawData, 'UTF-8', $request->getServer()->getCharset());
            }

            $rawData = $request->getServer()->processAnswer($rawData);

            $cleanRawData = CleanComments::removeNotices($rawData);
            foreach ($this->getRateLimitPatterns() as $pattern) {
                if (preg_match($pattern, $cleanRawData)) {
                    echo $cleanRawData;
                    throw new RateLimitException("Rate limit exceeded for {$request->getServer()->getName()}");
                }
            }

            foreach ($this->getNotFoundPatterns() as $pattern) {
                if (preg_match($pattern, $cleanRawData)) {
                    throw new NotFoundException("Nothing found by query '{$request->getQuery()}'");
                }
            }

            return $response->withAnswer($rawData);

        } catch (ClientRequestException|ClientResponseException $e) {
            $e->withRequest($request);
            if ($e instanceof ClientResponseException) {
                $e->withResponse($response);
            }
            throw $e;
        }
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
            '/(reached|exceeded) the maximum allowable/im',
            '/(reached|exceeded) your (query|request) limit/im',
            '/quota (exceeded|reached)/i',
            '/try again (later|after)/i',
            '/request cannot be processed/i',
            '/try your request again/i',
            '/(request|rate|query|connection) limit (exceeded|reached)/i',
            '/(exceeded|reached)( your| max)? (request|rate|query|connection|command) (rate|limit|rate limit)/i',
            '/excediste la cantidad permitida/i',
            '/too many (requests|queries)/i',
            '/server is busy/i',
            '/excessive querying/i',
        ];
    }

    protected function getNotFoundPatterns(): array
    {
        return [
            '/^[\W\s]*(no match|not found|no data found|nothing found)/im',
            '/is available for registration/i',
            '/queried (object|domain|record) does not exist/i',
            '/domain is available/i',
            '/domain( name)? not found/i',
            '/object not found/i',
            '/^status: (free|available)/mi',
            '/no matching objects found/i',
            '/lookup not available for this domain/i',
            '/domain( you requested)? is not known/i',
            '/(objects?|domains?|records?|entry|entries) not found/im',
            '/no (matching )?(objects?|domains?|records?|entry|entries) found/i',
            '/(object|domain) does not exist/i',
            '/rate limit exceeded/i',
        ];
    }

}
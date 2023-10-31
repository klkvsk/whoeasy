<?php

namespace Klkvsk\Whoeasy\Client;

use Klkvsk\Whoeasy\Client\Adapter\AdapterInterface;
use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
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

    public function lookup(
        string                     $query,
        string|ServerInfoInterface &$server = null,
        string                     &$queryType = null,
    ): string
    {
        $queryType ??= Request::guessQueryType($query);

        if (!$server) {
            $server = $this->registry->findByQuery($query, $queryType)
                ?? throw new ClientException('No server in registry matching query: ' . $query);
        }

        if (is_string($server)) {
            $server = $this->registry->findServer($server)
                ?? throw new ClientException('No server in registry matching name: ' . $query);
        }

        $request = $this->createRequest($server, $query, $queryType);
        $response = $this->handle($request);

        if (empty($response->getAnswer())) {
            throw (new ClientRequestException('Got empty response from server'))
                ->withRequest($request);
        }

        if (preg_match('/^clos(ing|ed) connection.+$/im', $response->getAnswer(), $m)) {
            throw (new ClientRequestException($m[0]))
                ->withRequest($request);
        }

        return $response->getAnswer();
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

        throw new ClientException('no adapter');
    }

}
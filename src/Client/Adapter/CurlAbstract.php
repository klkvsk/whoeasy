<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\Exception\ClientException;
use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\Exception\CurlRequestException;
use Klkvsk\Whoeasy\Client\Proxy\Provider\ProxyProviderInterface;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\Response;
use Klkvsk\Whoeasy\Client\ResponseInterface;
use Klkvsk\Whoeasy\Exception\MissingRequirementsException;

abstract class CurlAbstract implements AdapterInterface
{
    public function __construct(
        protected array                   $options = [],
        protected ?ProxyProviderInterface $proxyProvider = null,
    )
    {
        if (!extension_loaded('curl')) {
            throw new MissingRequirementsException('Curl extension is required for ' . self::class);
        }
    }

    abstract public function canHandle(RequestInterface $request): bool;

    /** @noinspection PhpComposerExtensionStubsInspection */
    public function handle(RequestInterface $request): ResponseInterface
    {
        $curl = curl_init();
        if (!$curl) {
            $error = error_get_last()['message'] ?? 'unknown reason';
            throw new ClientException('Unable to create cURL handler: ' . $error);
        }

        $proxy = $this->proxyProvider?->getProxy($request->getServer());

        curl_setopt_array($curl, $this->options);
        curl_setopt_array($curl, [
            CURLOPT_TIMEOUT_MS     => $request->getTimeout() * 1000,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROXY          => $proxy?->getUri(),
        ]);

        $this->setupCurl($curl, $request);

        try {
            return $this->execCurl($curl);
        } catch (ClientRequestException $e) {
            if ($e instanceof CurlRequestException) {
                if ($proxy && in_array($e->getCode(), [ 5, 7, 97 ])) {
                    $this->proxyProvider->markFailed($proxy);
                }
            }

            throw $e->withRequest($request);
        } finally {
            curl_close($curl);
        }
    }

    /** @noinspection PhpComposerExtensionStubsInspection */
    protected function execCurl($curl): ResponseInterface
    {
        $answer = curl_exec($curl);
        $errorMessage = curl_error($curl);
        $errorCode = curl_errno($curl);

        if ($errorCode || $errorMessage) {
            throw new CurlRequestException(sprintf('%s (code %d)', $errorMessage, $errorCode));
        }

        return new Response($answer);
    }

    abstract protected function setupCurl($curl, RequestInterface $request): void;

}
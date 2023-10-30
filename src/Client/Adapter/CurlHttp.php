<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\RequestInterface;

class CurlHttp extends CurlAbstract implements AdapterInterface
{
    public function canHandle(RequestInterface $request): bool
    {
        return str_starts_with($request->getServer()->getUri(), 'http:')
            || str_starts_with($request->getServer()->getUri(), 'https:');
    }

    /** @noinspection PhpComposerExtensionStubsInspection */
    protected function setupCurl($curl, RequestInterface $request): void
    {
        curl_setopt_array($curl, [
            CURLOPT_URL        => $request->getServer()->getUri(),
            CURLOPT_POST       => true,
            CURLOPT_POSTFIELDS => $request->getQueryString(),
        ]);
    }
}
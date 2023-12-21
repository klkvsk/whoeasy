<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\Exception\ClientRequestException;
use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\Response;
use Klkvsk\Whoeasy\Client\ResponseInterface;

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
        $query = preg_split('/\s+/', $request->getQueryString(), 3, PREG_SPLIT_NO_EMPTY);
        switch (count($query)) {
            case 1:
                if (preg_match('/^[A-Z]+$/', $query[0])) {
                    $method = $query[0];
                    $path = '/';
                } else {
                    $method = 'GET';
                    $path = $query[0];
                }
                $postData = null;
                break;
            case 2:
                $method = $query[0];
                $path = $query[1];
                $postData = null;
                break;
            case 3:
                $method = $query[0];
                $path = $query[1];
                $postData = $query[2];
                break;
            default:
                throw (new ClientRequestException('Invalid query string: ' . $request->getQueryString()))
                    ->withRequest($request);
        }

        $url = rtrim($request->getServer()->getUri(), '/') . $path;
        $options = [
            CURLOPT_URL => $url,
        ];
        if ($method !== 'GET') {
            $options[CURLOPT_CUSTOMREQUEST] = $method;
        }
        if ($postData) {
            $options[CURLOPT_POSTFIELDS] = $postData;
        }
        curl_setopt_array($curl, $options);
    }

    /** @noinspection PhpComposerExtensionStubsInspection */
    protected function execCurl($curl): string
    {
        $method = curl_getinfo($curl, CURLINFO_EFFECTIVE_METHOD);
        $data = curl_getinfo($curl, CURLINFO_EFFECTIVE_URL);
        if ($method === 'NONE') {
            return $data;
        }
        return parent::execCurl($curl);
    }


}
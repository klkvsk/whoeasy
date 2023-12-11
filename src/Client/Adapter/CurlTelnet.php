<?php

namespace Klkvsk\Whoeasy\Client\Adapter;

use Klkvsk\Whoeasy\Client\RequestInterface;

class CurlTelnet extends CurlAbstract implements AdapterInterface
{
    public function canHandle(RequestInterface $request): bool
    {
        return str_starts_with($request->getServer()->getUri(), 'whois://');
    }

    /** @noinspection PhpComposerExtensionStubsInspection */
    protected function setupCurl($curl, RequestInterface $request): void
    {
        $input = fopen('php://temp', 'r+');
        fwrite($input, $request->getQueryString() . "\r\n");
        rewind($input);
        $uri = $request->getServer()->getUri();
        $parsed = parse_url($uri);
        $host = $parsed['host'];
        $port = $parsed['port'] ?? 43;

        curl_setopt_array($curl, [
            CURLOPT_PROTOCOLS => CURLPROTO_TELNET,
            CURLOPT_URL       => "telnet://$host:$port",
            CURLOPT_INFILE    => $input,
        ]);

        switch ($request->getServer()->getName()) {
            case 'whois.fi':
                curl_setopt($curl, CURLOPT_TCP_FASTOPEN, true);
                break;

            default:
                break;
        }
    }

}
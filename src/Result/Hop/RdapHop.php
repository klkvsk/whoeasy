<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
readonly class RdapHop extends ProtocolHop
{
    /**
     * @param TInfo|null $info
     * @param array<mixed>|null $json
     */
    public function __construct(
        string $server,
        string $query,
        public string $url,
        public ?array $json,
        string $rawBody,
        ?AbstractInfo $info = null,
        ?\Throwable $error = null,
    ) {
        parent::__construct($server, $query, $rawBody, $info, $error);
    }

    public function toArray(): array
    {
        $data = [
            'server' => $this->server,
            'query' => $this->query,
            'url' => $this->url,
        ];

        if ($this->json !== null) {
            $data['responseJson'] = $this->json;
        } else {
            $data['response'] = $this->response;
        }

        if ($this->info !== null) {
            $data['info'] = $this->info->toArray();
        }

        if ($this->error !== null) {
            $data['error'] = [
                'class' => $this->error::class,
                'message' => $this->error->getMessage(),
            ];
        }

        return $data;
    }
}

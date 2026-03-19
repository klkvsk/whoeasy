<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
readonly class WhoisHop extends ProtocolHop
{
    /**
     * @param TInfo|null $info
     */
    public function __construct(
        string $server,
        string $query,
        string $rawText,
        ?AbstractInfo $info = null,
        ?\Throwable $error = null,
    ) {
        parent::__construct($server, $query, $rawText, $info, $error);
    }

    public function toArray(): array
    {
        $data = [
            'server' => $this->server,
            'query' => $this->query,
            'response' => $this->response,
        ];

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

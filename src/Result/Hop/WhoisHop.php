<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
readonly class WhoisHop extends ProtocolHop
{
    public function __construct(
        public string $server,
        public string $query,
        public string $rawText,
        /** @var TInfo */
        public ?AbstractInfo $info = null,
        public ?\Throwable $error = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'server' => $this->server,
            'query' => $this->query,
            'rawText' => $this->rawText,
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

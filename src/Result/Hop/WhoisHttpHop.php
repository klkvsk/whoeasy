<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Hop;

use Klkvsk\Whoeasy\Result\Info\AbstractInfo;

/**
 * @template TInfo of AbstractInfo
 */
readonly class WhoisHttpHop extends WhoisHop
{
    public function __construct(
        string $server,
        string $query,
        string $rawText,
        public string $httpUrl,
        public ?string $httpQueryFormat = null,
        public ?string $httpScraper = null,
        /** @var TInfo */
        ?AbstractInfo $info = null,
        ?\Throwable $error = null,
    ) {
        parent::__construct($server, $query, $rawText, $info, $error);
    }

    public function toArray(): array
    {
        $data = parent::toArray();
        $data['httpUrl'] = $this->httpUrl;

        if ($this->httpQueryFormat !== null) {
            $data['httpQueryFormat'] = $this->httpQueryFormat;
        }

        if ($this->httpScraper !== null) {
            $data['httpScraper'] = $this->httpScraper;
        }

        return $data;
    }
}

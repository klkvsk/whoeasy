<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class QueryResult
{
    public function __construct(
        public string $query,
        public StructuredResult $result,
        public ?HopResponses $rdap = null,
        public ?HopResponses $whois = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'query' => $this->query,
            'result' => $this->result->toArray(),
        ];

        if ($this->rdap !== null) {
            $data['rdap'] = $this->rdap->toArray();
        }

        if ($this->whois !== null) {
            $data['whois'] = $this->whois->toArray();
        }

        return $data;
    }
}

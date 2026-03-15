<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class QueryResult
{
    /**
     * @param RawResponse[] $whoisHops
     * @param RawResponse[] $rdapHops
     */
    public function __construct(
        public string $query,
        public StructuredResult $result,
        public array $whoisHops = [],
        public array $rdapHops = [],
    ) {}

    public function toArray(): array
    {
        $data = [
            'query' => $this->query,
            'result' => $this->result->toArray(),
        ];

        if ($this->whoisHops !== []) {
            $data['whoisHops'] = array_map(
                fn(RawResponse $r) => $r->toArray(),
                $this->whoisHops,
            );
        }

        if ($this->rdapHops !== []) {
            $data['rdapHops'] = array_map(
                fn(RawResponse $r) => $r->toArray(),
                $this->rdapHops,
            );
        }

        return $data;
    }
}

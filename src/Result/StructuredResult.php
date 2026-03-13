<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Enum\QueryType;

readonly class StructuredResult
{
    public function __construct(
        public QueryType $queryType,
        public ?DomainInfo $domain = null,
        public ?IpInfo $ip = null,
        public ?AsnInfo $asn = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'queryType' => $this->queryType->value,
        ];

        if ($this->domain !== null) {
            $data['domain'] = $this->domain->toArray();
        }

        if ($this->ip !== null) {
            $data['ip'] = $this->ip->toArray();
        }

        if ($this->asn !== null) {
            $data['asn'] = $this->asn->toArray();
        }

        return $data;
    }
}

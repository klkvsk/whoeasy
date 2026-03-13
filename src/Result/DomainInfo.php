<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class DomainInfo
{
    public function __construct(
        public ?string $name = null,
        public ?string $registrar = null,
        public ?Registrar $registrarInfo = null,
        public ?string $createdDate = null,
        public ?string $updatedDate = null,
        public ?string $expiresDate = null,
        /** @var string[] */
        public array $status = [],
        /** @var Nameserver[] */
        public array $nameservers = [],
        /** @var Contact[] */
        public array $contacts = [],
        public ?string $dnssec = null,
    ) {}

    public function toArray(): array
    {
        $data = [];

        if ($this->name !== null) {
            $data['name'] = $this->name;
        }

        if ($this->registrar !== null) {
            $data['registrar'] = $this->registrar;
        }

        if ($this->registrarInfo !== null) {
            $data['registrarInfo'] = $this->registrarInfo->toArray();
        }

        if ($this->createdDate !== null) {
            $data['createdDate'] = $this->createdDate;
        }

        if ($this->updatedDate !== null) {
            $data['updatedDate'] = $this->updatedDate;
        }

        if ($this->expiresDate !== null) {
            $data['expiresDate'] = $this->expiresDate;
        }

        if ($this->status !== []) {
            $data['status'] = $this->status;
        }

        if ($this->nameservers !== []) {
            $data['nameservers'] = array_map(
                fn(Nameserver $ns) => $ns->toArray(),
                $this->nameservers,
            );
        }

        if ($this->contacts !== []) {
            $data['contacts'] = array_map(
                fn(Contact $c) => $c->toArray(),
                $this->contacts,
            );
        }

        if ($this->dnssec !== null) {
            $data['dnssec'] = $this->dnssec;
        }

        return $data;
    }
}

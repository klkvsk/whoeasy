<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result\Info;

use Klkvsk\Whoeasy\Result\Info\Field\Contact;

readonly class IpInfo extends AbstractInfo
{
    public function __construct(
        public ?string $range = null,
        public ?string $networkName = null,
        public ?string $description = null,
        public ?int $asNumber = null,
        public ?string $country = null,
        public ?string $createdDate = null,
        public ?string $updatedDate = null,
        /** @var string[] */
        public array $status = [],
        /** @var Contact[] */
        public array $contacts = [],
    ) {}

    public function toArray(): array
    {
        $data = [];

        if ($this->range !== null) {
            $data['range'] = $this->range;
        }

        if ($this->networkName !== null) {
            $data['networkName'] = $this->networkName;
        }

        if ($this->description !== null) {
            $data['description'] = $this->description;
        }

        if ($this->asNumber !== null) {
            $data['asNumber'] = $this->asNumber;
        }

        if ($this->country !== null) {
            $data['country'] = $this->country;
        }

        if ($this->createdDate !== null) {
            $data['createdDate'] = $this->createdDate;
        }

        if ($this->updatedDate !== null) {
            $data['updatedDate'] = $this->updatedDate;
        }

        if ($this->status !== []) {
            $data['status'] = $this->status;
        }

        if ($this->contacts !== []) {
            $data['contacts'] = array_map(
                fn(Contact $c) => $c->toArray(),
                $this->contacts,
            );
        }

        return $data;
    }
}

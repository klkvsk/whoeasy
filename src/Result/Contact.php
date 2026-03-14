<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

use Klkvsk\Whoeasy\Parser\Data\ContactType;

readonly class Contact
{
    public function __construct(
        public ContactType $type,
        public ?string $name = null,
        public ?string $organization = null,
        public ?string $email = null,
        public ?string $phone = null,
        public ?string $fax = null,
        public ?string $address = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'type' => $this->type->value,
        ];

        if ($this->name !== null) {
            $data['name'] = $this->name;
        }

        if ($this->organization !== null) {
            $data['organization'] = $this->organization;
        }

        if ($this->email !== null) {
            $data['email'] = $this->email;
        }

        if ($this->phone !== null) {
            $data['phone'] = $this->phone;
        }

        if ($this->fax !== null) {
            $data['fax'] = $this->fax;
        }

        if ($this->address !== null) {
            $data['address'] = $this->address;
        }

        return $data;
    }
}

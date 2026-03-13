<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Result;

readonly class Registrar
{
    public function __construct(
        public ?string $name = null,
        public ?string $ianaId = null,
        public ?string $url = null,
        public ?string $abuseEmail = null,
        public ?string $abusePhone = null,
    ) {}

    public function toArray(): array
    {
        $data = [];

        if ($this->name !== null) {
            $data['name'] = $this->name;
        }

        if ($this->ianaId !== null) {
            $data['ianaId'] = $this->ianaId;
        }

        if ($this->url !== null) {
            $data['url'] = $this->url;
        }

        if ($this->abuseEmail !== null) {
            $data['abuseEmail'] = $this->abuseEmail;
        }

        if ($this->abusePhone !== null) {
            $data['abusePhone'] = $this->abusePhone;
        }

        return $data;
    }
}

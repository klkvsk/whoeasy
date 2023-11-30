<?php

namespace Klkvsk\Whoeasy\Parser\Data;

class ContactResult extends AbstractResult
{
    public ?string $name = null;
    public ?string $address = null;
    public ?string $phone = null;
    public ?string $email = null;

    public function toArray(): array
    {
        $array = parent::toArray();
        if (empty($array['type'])) {
            unset($array['type']);
        }
        return $array;
    }


}
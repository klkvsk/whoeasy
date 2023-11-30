<?php

namespace Klkvsk\Whoeasy\Parser\Data;

class AbstractResult extends \stdClass implements \JsonSerializable
{
    public ?string $type = null;

    public function toArray(): array
    {
        $array = (array)$this;
        array_walk_recursive($array, function (&$value) {
            if ($value instanceof self) {
                $value = $value->toArray();
            }
            if ($value instanceof \DateTimeInterface) {
                $value = $value->format('Y-m-d H:i:s');
            }
        });
        return $array;
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
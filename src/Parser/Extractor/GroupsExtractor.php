<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

class GroupsExtractor extends Extractor
{
    /** @var FieldsExtractor[] */
    public readonly array $groups;

    public function __construct(array $groups)
    {
        $groups = array_map(
            fn ($g) => $g instanceof Extractor ? $g : new FieldsExtractor($g),
            $groups
        );

        $this->groups = $groups;
    }

    public function group(string ...$patterns): FieldsExtractor
    {
        foreach ($patterns as $pattern) {
            foreach ($this->groups as $group) {
                $value = $group->field($pattern);
                if ($value !== null) {
                    return $group;
                }
            }
        }

        return new FieldsExtractor([]);
    }

    public function skip(int $numGroups): self
    {
        return new self(array_slice($this->groups, $numGroups));
    }

    public function field(string ...$patterns): mixed
    {
        foreach ($patterns as $pattern) {
            foreach ($this->groups as $group) {
                $value = $group->field($pattern);
                if ($value) {
                    return $value;
                }
            }
        }
        return null;
    }


}
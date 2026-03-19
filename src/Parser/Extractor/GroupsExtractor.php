<?php

declare(strict_types=1);

namespace Klkvsk\Whoeasy\Parser\Extractor;

class GroupsExtractor extends Extractor
{
    /** @var FieldsExtractor[] */
    public readonly array $groups;

    /** @param array<array<string, mixed>|FieldsExtractor> $groups */
    public function __construct(array $groups)
    {
        /** @var FieldsExtractor[] $mapped */
        $mapped = array_map(
            fn (array|FieldsExtractor $g) => $g instanceof FieldsExtractor ? $g : new FieldsExtractor($g),
            $groups
        );

        $this->groups = $mapped;
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
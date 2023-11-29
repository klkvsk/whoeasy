<?php

namespace Klkvsk\Whoeasy\Parser\Extractor;

class GroupsExtractor extends Extractor
{
    /** @var FieldsExtractor[] */
    public readonly array $groups;

    public function __construct(array $groups)
    {
        $gg = [];
        foreach ($groups as $group) {
            $gg[] = new FieldsExtractor($group);
        }

        $this->groups = $gg;
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
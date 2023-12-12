<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class BlockFields extends SimpleFields
{
    public function process(WhoisAnswer $answer): void
    {
        $blockFields = [];

        $numBlocks = preg_match_all('/(?<=\n|^)([a-z0-9- ]+):\n+((?:[ \t]+.+?[\n$])+)/i', $answer->rawData, $m);
        if (!$numBlocks) {
            return;
        }
        for ($i = 0; $i < $numBlocks; $i++) {
            $field = $m[1][$i];
            $value = explode("\n", $m[2][$i]);
            $value = array_map(trim(...), $value);
            $value = array_filter($value);
            $value = match (count($value)) {
                0 => null,
                1 => $value[0],
                default => $value,
            };
            $value = array_values($value);
            self::set($blockFields, $field, $value);
        }

        $answer->fields ??= [];
        $answer->fields = array_merge($answer->fields, $blockFields);

        $answer->groups ??= [];
        $answer->groups[] = $blockFields;
    }

    public static function set(array &$fields, string $fieldName, $fieldValue): array
    {
        if (isset($fields[$fieldName])) {
            if (!is_array($fields[$fieldName])) {
                $fields[$fieldName] = [ $fields[$fieldName] ];
            }
            $fields[$fieldName][] = $fieldValue;
        } else {
            $fields[$fieldName] = $fieldValue;
        }

        return $fields;
    }

}
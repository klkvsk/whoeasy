<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class BlockFields extends SimpleFields
{
    public function process(WhoisAnswer $answer): void
    {
        $this->processBlocks('/(?<=\n|^)([a-z0-9- ]+):\n+((?:[ \t]+.+?[\n$])+)/i', $answer);

        // com.tr
        $this->processBlocks('/(?<=\*\* )([a-z0-9- ]+):\n+((?:[ \t]*.+?[\n$])+)/i', $answer);

    }

    protected function processBlocks(string $regex, WhoisAnswer $answer)
    {
        $blockFields = [];

        $numBlocks = preg_match_all($regex, $answer->text, $m);
        if (!$numBlocks) {
            return;
        }
        for ($i = 0; $i < $numBlocks; $i++) {
            $field = $m[1][$i];
            $lines = explode("\n", $m[2][$i]);
            $lines = array_map(trim(...), $lines);
            $lines = array_filter($lines);
            foreach ($lines as $line) {
                if (str_contains($line, ': ')) {
                    [ $key, $value ] = $this->parseLine($line);
                    self::set($blockFields, $field . ' ' . $key, $value);
                } else {
                    self::set($blockFields, $field, $line);
                }
            }
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
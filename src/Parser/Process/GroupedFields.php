<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class GroupedFields extends SimpleFields
{
    public function process(WhoisAnswer $answer): void
    {
        $groups = [];
        $fields = [];
        foreach ($answer->lines() as $line) {
            if (trim($line) === '') {
                if ($fields) {
                    $groups[] = $fields;
                    $fields = [];
                }
            }
            [ $fieldName, $fieldValue ] = $this->parseLine($line);
            if ($fieldName && $fieldValue) {
                self::set($fields, $fieldName, $fieldValue);
            }
        }
        if ($fields) {
            $groups[] = $fields;
        }

        $answer->groups = $groups;
    }

}
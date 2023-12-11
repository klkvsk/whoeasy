<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class SimpleFields implements DataProcessorInterface
{
    public function __construct(
        protected bool $skipRedactedForPrivacy = true
    )
    {
    }

    public function process(WhoisAnswer $answer): void
    {
        $fields = [];
        foreach ($answer->lines() as $line) {
            [ $fieldName, $fieldValue ] = $this->parseLine($line);
            if ($fieldName && $fieldValue) {
                self::set($fields, $fieldName, $fieldValue);
            }
        }
        $answer->fields = $fields;
        $answer->groups = [ $fields ];
    }

    /**
     * @param string $line
     * @return list<?string, ?string>
     */
    protected function parseLine(string $line): array
    {
        if (!preg_match('/^\s*([a-z0-9 -]+)[\s.:-]*[.:-]\s*(.+)\s*$/i', $line, $match)) {
            return [ null, null ];
        }

        $fieldName = trim($match[1]);
        $fieldValue = trim($match[2]);

        $fieldName = strtolower($fieldName);

        if ($this->skipRedactedForPrivacy) {
            if (preg_match('/(redacted for privacy|query the rdds service)/i', $line)) {
                $fieldValue = null;
            }
        }

        if ($fieldValue === '') {
            $fieldValue = null;
        }

        return [ $fieldName, $fieldValue ];
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
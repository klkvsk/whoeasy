<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;


class JsonToText implements DataProcessorInterface
{
    public function process(WhoisAnswer $answer): void
    {
        $text = $answer->text;

        if (!str_starts_with($text, '{') && !str_starts_with($text, '[')) {
            return;
        }
        $data = json_decode($text, true);
        if (!$data) {
            return;
        }

        $answer->text = $this->formatArray($data);
    }

    protected function formatArray(array $array, int $level = 0): string
    {
        if (self::arrayIsScalarList($array)) {
            return implode(', ', $array);
        }

        $text = '';
        $indent = str_repeat(' ', $level * 2);
        uasort($array, function ($a, $b) {
            $ac = !is_array($a) || self::arrayIsScalarList($a);
            $bc = !is_array($b) || self::arrayIsScalarList($b);
            return $bc <=> $ac;
        });
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                if (is_string($key)) {
                    $text .= "\n{$indent}[$key]";
                }
                $text .= "\n" . $this->formatArray($value, $level + 1);
            } else {
                $text .= "{$indent}$key: $value\n";
            }
        }

        return $text;
    }

    protected static function arrayIsScalarList(array $array): bool
    {
        if (!array_is_list($array)) {
            return false;
        }
        foreach ($array as $item) {
            if (!is_scalar($item)) {
                return false;
            }
        }
        return true;
    }

}
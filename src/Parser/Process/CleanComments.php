<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

/**
 * to do: https://github.com/rfc1036/whois/blob/next/data.h#L22
 */
class CleanComments implements DataProcessorInterface
{
    public function process(WhoisAnswer $answer): void
    {
        $text = $answer->rawData;
        $text = self::removeCommentedLines($text);
        $text = self::removeNotices($text);
        $text = self::stripTags($text);
        $text = self::normalizeNewLines($text);
        $answer->text = $text;
    }

    public static function removeCommentedLines(string $text): string
    {
        return preg_replace('/^\s*[%#;\/<>].*/m', "\n", $text);
    }

    public static function removeNotices(string $text): string
    {
        $regexps = [
            '/^\s*for more information.+/im',
            '/^.+whois inaccuracy complaint form.+$/im',
            '/\nNOTICE:[\s\S]+?\n\n/',
            '/\nTERMS OF USE:[\s\S]+?\n\n/',
            '/^\s*terms of use:.+/im',
        ];
        foreach ($regexps as $regexp) {
            $text = preg_replace($regexp, "\n", $text);
        }
        return $text;
    }

    public static function stripTags(string $text): string
    {
        return strip_tags($text);
    }

    public static function normalizeNewLines(string $text): string
    {
        // leave no more than 2 empty lines in between blocks
        $text = preg_replace("/\n{3,}/", "\n\n", $text);
        return trim($text);
    }

}
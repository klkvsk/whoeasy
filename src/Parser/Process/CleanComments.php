<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Exception\ParserException;

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
            // multiline that contains certain phrases
            '/(?<=\n\n|^)(.\n?)*'
                . '.*(you agree to |sole discretion|does not guarantee|reserves the right|for lawful purposes).*'
                . '(.\n?)*(?=\n\n|$)/i',
            // multiline that starts and ends like a sentence
            '/(?<=\n|^)(The|A|An|For|By|All) ((.+?\n)+(.+?\.)|.{80,})(?=\n\n|$)/',

            '/^\W*for more information.+/im',
            '/^.+whois inaccuracy complaint form.+$/im',
            '/^.+does not guarantee.+$/im',
            '/^.+reserves the right to .+$/im',
            '/\nNOTICE[\s\S]+?(?=\n\n)/',
            '/(?<=\n|^)NOTE[\s\S]+?(?=\n\n|$)/',
            '/\nTERMS OF USE[\s\S]+?\n\n/',
            '/^\s*terms of use:.+/im',
            '/^>>>.+<<<$/m',
            '/^\[ JPRS [\s\S]+?(?=\n[^\[])/'
        ];
        foreach ($regexps as $regexp) {
            $text = preg_replace($regexp, "\n", $text);
            $text = trim($text);
            if (!$text) {
                throw new ParserException("Failed to remove notices with regexp: $regexp");
            }
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
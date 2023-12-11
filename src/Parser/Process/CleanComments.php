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

        // remove lines starting with: '#', ';', '/', '<', '>', '%'
        $text = preg_replace('/^\s*[%#;\/<>].*/m', "\n", $text);
        $text = preg_replace('/^\s*for more information.+/im', "\n", $text);
        $text = preg_replace('/^.+whois inaccuracy complaint form.+$/im', "\n", $text);
        $text = preg_replace('/\nNOTICE:[\s\S]+?\n\n/', "<>\n", $text);
        $text = preg_replace('/\nTERMS OF USE:[\s\S]+?\n\n/', "<>\n", $text);
        $text = preg_replace('/^\s*terms of use:.+/im', "\n", $text);

        // leave no more than 2 empty lines in between blocks
        $text = preg_replace("/\n{3,}/", "\n\n", $text);
        $text = strip_tags($text);

        $text = trim($text);

        $answer->text = $text;
    }

}
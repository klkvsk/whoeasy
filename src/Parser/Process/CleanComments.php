<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;

class CleanComments implements DataProcessorInterface
{
    public function process(WhoisAnswer $answer): void
    {
        $text = $answer->rawData;

        // remove lines starting with: '#', ';', '/', '<', '>', '%'
        $text = preg_replace('/^\s*[%#;\/<>].+/m', '', $text);
        $text = preg_replace('/^\s*terms of use:.+/im', '', $text);
        $text = preg_replace('/^\s*for more information.+/im', "", $text);
        $text = preg_replace('/^.+whois inaccuracy complaint form.+$/im', "", $text);

        // convert newlines
        $text = str_replace("\r", "", $text);

        // leave no more than 2 empty lines in between blocks
        $text = preg_replace("/\n{3,}/", '', $text);

        $text = trim($text);

        $answer->text = $text;
    }

}
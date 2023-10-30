<?php

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use DateTime;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

class Venez extends Regex
{

    protected bool $convertFromHtml = true;

    protected ?string $htmlBlock = '/<h3>WHOIS (.*?)<fieldset id="fieldactu">/i';

    protected array $blocks = [
        1 => '/Statut domaine: (.*?)<\/b>/im',
        2 => '/Date de cr&eacute;ation: (.*?)<\/b>/im',
        3 => '/Derni&egrave;re modification: (.*?)<\/b>/im',
        4 => '/Type: (.*?)<\/b>/im',
        5 => '/Personne: (.*?)<\/b>/im',
        6 => '/Raison sociale: (.*?)<\/b>/im',
        7 => '/Adresse &eacute;lectronique: (.*)<\/a>/im',
    ];

    protected array $blockItems = [
        1 => [
            '/<b>(.*?)<\/b>/i' => 'status',
        ],
        2 => [
            '/<b>(.*?)<\/b>/i' => 'created',
        ],
        3 => [
            '/<b>(.*?)<\/b>/i' => 'changed',
        ],
        4 => [
        ],
        5 => [
            '/<b>(.*?)<\/b>/i' => 'contacts:owner:name',
        ],
        6 => [
            '/<b>(.*?)<\/b>/i' => 'contacts:owner:organization',
        ],
        7 => [
            '/<a href="mailto:(.*?)">/i' => 'contacts:owner:email',
        ],
    ];

    protected ?string $available = '/Domaine non trouv&eacute;/i';


    public function postProcess(object $WhoisParser): void
    {
        $result = $WhoisParser->getResult();

        foreach ($result->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->email = html_entity_decode($contactObject->email);
            }
        }

        $dateFields = [ 'created', 'changed', 'expires' ];
        $originalDateFormat = 'd/m/Y à H:i:s';
        foreach ($dateFields as $field) {
            if (isset($result->$field) && strlen($result->$field)) {
                $dt = DateTime::createFromFormat($originalDateFormat, $result->$field);
                if (is_object($dt)) {
                    $result->$field = $dt->format('Y-m-d H:i:s');
                }
            }
        }
    }


    public function translateRawData(string $rawData): string
    {
        return utf8_encode($rawData);
    }
}

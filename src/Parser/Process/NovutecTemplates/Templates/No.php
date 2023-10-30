<?php

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\KeyValue;

class No extends KeyValue
{

    protected array $regexKeys = [
        'name'                   => '/^Domain Name$/i',
        'created'                => '/^Domain Created$/i',
        'changed'                => '/^Domain Last Updated$/i',
        // Registrar
        'registrar:id'           => '/^Registrar Handle$/i',
        // Contacts: Owner
        'contacts:owner:handle'  => '/^Domain Holder Handle$/i',
        'contacts:owner:type'    => '/^Type$/i',
        'contacts:owner:name'    => '/^Name$/i',
        'contacts:owner:address' => '/^Post Address$/i',
        'contacts:owner:city'    => '/^Postal Area$/i',
        'contacts:owner:zipcode' => '/^Postal Code$/i',
        'contacts:owner:country' => '/^Country$/i',
        'contacts:owner:phone'   => '/^Phone Number$/i',
        'contacts:owner:fax'     => '/^Fax Number$/i',
        'contacts:owner:email'   => '/^Email Address$/i',
        'contacts:owner:created' => '/^Holder Created$/i',
        'contacts:owner:changed' => '/^Holder Last Updated$/i',
        // Contacts: Admin
        'contacts:admin:handle'  => '/^Legal-c Handle$/i',
        // Contacts: Tech
        'contacts:tech:handle'   => '/^Tech-c Handle$/i',
    ];

    protected ?string $available = '/No match/i';


    protected function reformatData(): void
    {
        $this->data = $this->reformatDataArray($this->data);
    }


    protected function reformatDataArray($dataArray)
    {
        $firstValueKeys = [ 'NORID Handle', 'Created', 'Last updated' ];
        foreach ($dataArray as $key => $value) {
            unset($dataArray[$key]);
            $key = rtrim($key, '.');

            if (is_array($value)) {
                if (in_array($key, $firstValueKeys)) {
                    $dataArray['Domain ' . $key] = array_shift($value);
                    $dataArray['Holder ' . $key] = array_shift($value);
                    continue;
                }

                $value = array_unique($value);
                if (count($value) == 1) {
                    $value = array_shift($value);
                }
            }

            $dataArray[$key] = $value;
        }

        return $dataArray;
    }

}

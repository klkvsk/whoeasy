<?php
/**
 * Novutec Domain Tools
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\Whois\Parser\Templates
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

/**
 * Template for .UY
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Uy extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/titular:(?>[\x20\t]*)(.*?)(?=nombre de dominio:)/is',
                                2 => '/contacto administrativo:(?>[\x20\t]*)(.*?)(?=contacto tecnico)/is',
                                3 => '/contacto tecnico:(?>[\x20\t]*)(.*?)(?=contacto de cobranza)/is',
                                4 => '/contacto de cobranza:(?>[\x20\t]*)(.*?)(?=(fecha de vencimiento|ultima actualizacion))/is',
                                5 => '/(fecha de vencimiento|ultima actualizacion):(?>[\x20\t]*)(.*?)(?=servidor\(es\) de nombres de dominio)/is',
                                6 => '/servidor\(es\) de nombres de dominio:(?>[\x20\t]*)(.*?)(?=nic-uruguay)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/titular:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:owner:address' ],
        2 => [
            '/contacto administrativo:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:admin:address' ],
        3 => [ '/contacto tecnico:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:tech:address' ],
        4 => [
            '/contacto de cobranza:(?>[\x20\t\n]*)(.*?)$/is' => 'contacts:billing:address' ],
        5 => [ '/fecha de vencimiento:(?>[\x20\t]*)(.*?)$/im' => 'expires',
               '/ultima actualizacion:(?>[\x20\t]*)(.*?)$/im' => 'changed',
               '/fecha de creacion:(?>[\x20\t]*)(.*?)$/im'    => 'created',
               '/estatus del dominio:(?>[\x20\t]*)(.*?)$/im'  => 'status' ],
        6 => [ '/\n(?>[\x20\t]+)- (.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No match for/i';

    /**
     * After parsing do something
     *
     * Fix contact addresses
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = [];

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));

                preg_match('/(.*?)(?>[\x20\t]*)\((.*?)\)(?>[\x20\t]*)(.*?)$/im', $filteredAddress[0], $matches);
                $contactObject->name = $matches[1];
                $contactObject->handle = $matches[2];
                $contactObject->email = $matches[3];

                if (sizeof($filteredAddress) === 5) {
                    $contactObject->organization = $filteredAddress[1];
                    $contactObject->address = [ $filteredAddress[2], $filteredAddress[3] ];
                } else {
                    $contactObject->address = [ $filteredAddress[1], $filteredAddress[2] ];
                }

                if (stripos(end($filteredAddress), 'fax')) {
                    $matches = explode(' (FAX) ', end($filteredAddress));
                    $contactObject->phone = $matches[0];
                    $contactObject->fax = $matches[1];
                } else {
                    $contactObject->phone = end($filteredAddress);
                }
            }
        }
    }
}
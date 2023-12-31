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
 * Template for Switch Domains .CH / .LI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Switchnic extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/holder of domain name:\n(.*?)(?=contractual language)/is',
                                2 => '/technical contact:\n(.*?)(?=dnssec)/is', 3 => '/dnssec:(.*?)(?=name servers)/is',
                                4 => '/name servers:\n(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/holder of domain name:\n(.*)$/is' => 'contacts:owner:address' ],
        2 => [ '/technical contact:\n(.*?)$/is' => 'contacts:tech:address' ],
        3 => [ '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec' ],
        4 => [ '/\n(?>[\x20\t]*)(.+)$/im'                    => 'nameserver',
               '/\n(?>[\x20\t]*)(.+)(?>[\x20\t]*)\[.+\]$/im' => 'nameserver',
               '/\n(?>[\x20\t]*).+(?>[\x20\t]*)\[(.+)\]$/im' => 'ips' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/We do not have an entry in our database matching your query/i';

    /**
     * After parsing ...
     *
     * Fix contact addresses and set dnssec
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if ($ResultSet->dnssec === 'Y') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));


                switch (sizeof($filteredAddress)) {
                    case 6:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[5];
                        $contactObject->city = $filteredAddress[4];
                        $contactObject->address = $filteredAddress[3];
                        break;
                    case 5:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[4];
                        $contactObject->city = $filteredAddress[3];
                        $contactObject->address = $filteredAddress[2];
                        break;
                    default:
                        //do nothing.
                }
            }
        }
    }
}

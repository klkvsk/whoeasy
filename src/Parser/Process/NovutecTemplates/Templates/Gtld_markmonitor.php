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
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates;

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

/**
 * Template for IANA #292
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Gtld_markmonitor extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/Registrant:(.*?)(?=Domain Name:)/is',
                                2 => '/Administrative Contact:(.*)(?=Technical Contact)/is',
                                3 => '/Technical Contact(, Zone Contact)?:(.*?)(?=Created on)/is',
                                4 => '/Zone Contact:(.*?)(?=Created on)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [ 1 => [ '/Registrant:(.*?)$/is' => 'contacts:owner:address' ],
                                    2 => [ '/Administrative Contact:(.*)$/is' => 'contacts:admin:address' ],
                                    3 => [ '/Technical Contact(, Zone Contact)?:(.*?)$/is' => 'contacts:tech:address' ],
                                    4 => [ '/Zone Contact:(.*?)$/is' => 'contacts:zone:address' ] ];

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));

                $contactObject->name = $filteredAddress[0];
                $contactObject->organization = $filteredAddress[1];
                $contactObject->city = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
                $contactObject->address = $filteredAddress[2];

                $lastEntries = explode(' ', $filteredAddress[5]);

                $contactObject->email = $lastEntries[0];
                $contactObject->phone = $lastEntries[1];

                if (isset($lastEntries[3])) {
                    $contactObject->fax = $lastEntries[3];
                }
            }
        }
    }
}
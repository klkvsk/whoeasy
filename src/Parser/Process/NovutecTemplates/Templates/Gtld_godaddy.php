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
 * Template for IANA #146, #440
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Gtld_godaddy extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [
        1 => '/Domain Name:(.*?)(?=Registrar Abuse Contact Email)/is',
        2 => '/Registrant:(.*?)(?=Administrative Contact)/is',
        3 => '/Administrative Contact:(.*?)(?=Technical Contact)/is',
        4 => '/Technical Contact:(.*?)(?=Domain servers in listed order)/is',
    ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/Registrar Registration Expiration Date:\n(?>[\x20\t]*)(.+)/is' => 'expires' ],
        2 => [ '/Registrant:\n(?>[\x20\t]*)(.+)/is' => 'contacts:owner:address' ],
        3 => [ '/Administrative Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:admin:address' ],
        4 => [ '/Technical Contact:\n(?>[\x20\t]*)(.+)/is' => 'contacts:tech:address' ],
    ];

    /**
     * After parsing do something
     *
     * Fix addresses
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

                if (sizeof($filteredAddress) === 4) {
                    $contactObject->name = $filteredAddress[0];
                    $contactObject->address = $filteredAddress[1];
                    $contactObject->city = $filteredAddress[2];
                    $contactObject->country = $filteredAddress[3];
                } else {
                    preg_match('/(?>[\x20\t]*)(.*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[0], $matches);

                    if (sizeof($matches) === 0) {
                        $contactObject->name = $filteredAddress[0];
                    } else {
                        if (isset($matches[1])) {
                            $contactObject->name = trim($matches[1]);
                        }

                        if (isset($matches[2])) {
                            $contactObject->email = trim($matches[2]);
                        }
                    }

                    $contactObject->organization = $filteredAddress[1];
                    $contactObject->address = $filteredAddress[2];
                    $contactObject->city = $filteredAddress[3];
                    $contactObject->country = $filteredAddress[4];

                    if (isset($filteredAddress[5])) {
                        preg_match('/(?>[\x20\t]*)(.*?)(?>[\x20\t]{1,})Fax -- (.+)/i', $filteredAddress[5], $matches);

                        if (isset($matches[1])) {
                            $contactObject->phone = $matches[1];
                        }

                        if (isset($matches[2])) {
                            $contactObject->fax = $matches[2];
                        }
                    }
                }
            }
        }
    }
}
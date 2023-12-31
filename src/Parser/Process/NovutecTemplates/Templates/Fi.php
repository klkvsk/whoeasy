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
 * Template for .FI
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Fi extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/status:(?>[\x20\t]*)(.*?)(?=more information is)/is',
                                2 => '/descr:(?>[\x20\t]*)(.*?)(?=status)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/created:(?>[\x20\t]*)(.+)$/im'        => 'created',
               '/modified:(?>[\x20\t]*)(.+)$/im'       => 'changed',
               '/expires:(?>[\x20\t]*)(.+)$/im'        => 'expires',
               '/status:(?>[\x20\t]*)(.+)$/im'         => 'status',
               '/dnssec:(?>[\x20\t]*)(.+)$/im'         => 'dnssec',
               '/nserver:(?>[\x20\t]*)(.+) \[.+\]$/im' => 'nameserver' ],
        2 => [ '/descr:(?>[\x20\t]*)(.+)$/im'   => 'contacts:owner:organization',
               '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
               '/phone:(?>[\x20\t]*)(.+)$/im'   => 'contacts:owner:phone' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/domain not found/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true. Furthermore
     * we have to fix the owner address, because the WHOIS output is not
     * well formed.
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if ($ResultSet->dnssec !== 'no') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->organization = utf8_encode($contactObject->organization[0]);
                $contactObject->name = $contactObject->address[0];
                $contactObject->zipcode = $contactObject->address[2];
                $contactObject->city = $contactObject->address[3];
                $contactObject->address = $contactObject->address[1];
            }
        }
    }
}
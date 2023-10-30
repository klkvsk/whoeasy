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
 * Template for .UK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Uk extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/registrant:(.*?)(?=registrant type:)/is',
                                2 => '/address:(.*?)(?=registrar:)/is', 3 => '/registrar:(.*?)(?=relevant dates:)/is',
                                4 => '/relevant dates:(.*?)(?=registration status:)/is',
                                5 => '/registration status:(.*?)(?=name servers:)/is',
                                6 => '/name servers:(.*?)(?=whois lookup made)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/registrant:(?>[\n\x20\t]*)(.+)/im' => 'contacts:owner:name' ],
        2 => [ '/address:(?>[\n\x20\t]*)(.+)$/is' => 'contacts:owner:address' ],
        3 => [ '/registrar:(?>[\n\x20\t]*)(.+) \[.+\]$/im' => 'registrar:name',
               '/url:(?>[\n\x20\t]*)(.+)$/im'              => 'registrar:url',
               '/\[tag = (.+)\]$/im'                       => 'registrar:id' ],
        4 => [ '/registered on:(?>[\x20\t]*)(.+)$/im' => 'created',
               '/expiry date:(?>[\x20\t]*)(.*)$/im'   => 'expires',
               '/last updated:(?>[\x20\t]*)(.+)$/im'  => 'changed' ],
        5 => [ '/registration status:(?>[\n\x20\t]*)(.+)/im' => 'status' ],
        6 => [ '/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/This domain name has not been registered/i';

    /**
     * After parsing do something
     *
     * Fix owner address
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));

                $contactObject->address = $filteredAddress[0];
                $contactObject->city = $filteredAddress[1];
                $contactObject->state = $filteredAddress[2];
                $contactObject->zipcode = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
            }
        }
    }
}
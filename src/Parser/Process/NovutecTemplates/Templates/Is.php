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
 * Template for .IS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Is extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain:(?>[\x20\t]*)(.*?)(?=(person|role):)/is',
                                2 => '/(person|role):(?>[\x20\t]*)(.*?)([\n]{2}|$)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^status:(?>[\x20\t]*)(.+)$/im'    => 'status',
               '/^admin-c:(?>[\x20\t]*)(.+)$/im'   => 'network:contacts:admin',
               '/^tech-c:(?>[\x20\t]*)(.+)$/im'    => 'network:contacts:tech',
               '/^zone-c:(?>[\x20\t]*)(.+)$/im'    => 'network:contacts:zone',
               '/^billing-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:billing',
               '/^nserver:(?>[\x20\t]*)(.+)$/im'   => 'nameserver',
               '/^created:(?>[\x20\t]*)(.+)$/im'   => 'created',
               '/^expires:(?>[\x20\t]*)(.+)$/im'   => 'expires' ],
        2 => [ '/^nic-hdl:(?>[\x20\t]*)(.+)$/im'       => 'contacts:handle',
               '/^(person|role):(?>[\x20\t]*)(.+)$/im' => 'contacts:name',
               '/^address:(?>[\x20\t]*)(.+)$/im'       => 'contacts:address',
               '/^phone:(?>[\x20\t]*)(.+)$/im'         => 'contacts:phone',
               '/^fax-no:(?>[\x20\t]*)(.+)$/im'        => 'contacts:fax',
               '/^e-mail:(?>[\x20\t]*)(.+)$/im'        => 'contacts:email',
               '/^changed:(?>[\x20\t]*)(.+)$/im'       => 'contacts:changed' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No entries found for query/i';

    /**
     * After parsing ...
     *
     * Convert UTF-8 in contact handles and rawdata
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->name = utf8_encode($contactObject->name);

                if (is_array($contactObject->address)) {
                    $contactObject->address = array_map('utf8_encode', $contactObject->address);
                } else {
                    $contactObject->address = utf8_encode($contactObject->address);
                }
            }
        }

    }
}
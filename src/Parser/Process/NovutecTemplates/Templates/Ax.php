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
 * Template for .AX
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ax extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Template
     */
    protected array $blocks = [ 1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Name Server)/is',
                                2 => '/Name Server 1:(?>[\x20\t]*)(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/Name:(?>[\x20\t]*)(.+)$/im'                   => 'contacts:owner:name',
               '/Administrative Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
               '/Email address:(?>[\x20\t]*)(.+)$/im'          => 'contacts:admin:email',
               '/Address:(?>[\x20\t]*)(.+)$/im'                => 'contacts:admin:address',
               '/Country:(?>[\x20\t]*)(.+)$/im'                => 'contacts:admin:country',
               '/Telephone:(?>[\x20\t]*)(.+)$/im'              => 'contacts:admin:phone',
               '/Created:(?>[\x20\t]*)(.+)$/im'                => 'created' ],
        2 => [ '/Name Server [0-9]:(?>[\x20\t]*)(.+)$/im' => 'nameserver' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No records matching/i';

    /**
     * After parsing ...
     *
     * Fix UTF-8
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
                $contactObject->name = utf8_encode($contactObject->name);
                if (is_array($contactObject->address)) {
                    foreach ($contactObject->address as $elem) {
                        $filteredAddress[] = utf8_encode($elem);
                    }
                    $contactObject->address = $filteredAddress;
                } else {
                    $contactObject->address = utf8_encode($contactObject->address);
                }
            }
        }
    }
}
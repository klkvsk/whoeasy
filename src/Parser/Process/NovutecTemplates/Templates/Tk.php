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
 * Template for .TK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Tk extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/organisation:\n(.*?)(?=domain nameservers)/is',
                                2 => '/domain registered:(?>[\x20\t]*)(.*?)$/is',
                                3 => '/domain nameservers:\n(?>[\x20\t]*)(.*?)(?=domain registered)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [ 1 => [ '/organisation:(.*?)$/is' => 'contacts:owner:address' ],
                                    2 => [ '/domain registered:(?>[\x20\t]*)(.+)$/im'     => 'created',
                                           '/record will expire on:(?>[\x20\t]*)(.+)$/im' => 'expires' ],
                                    3 => [ '/\n(?>[\x20\t]+)(.+)$/im'        => 'nameserver',
                                           '/\n(?>[\x20\t]+)(.+) \(.+\)$/im' => 'nameserver',
                                           '/\n(?>[\x20\t]+).+ \((.+)\)$/im' => 'ips' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Invalid query or domain name not known in/i';

    /**
     * After parsing do something
     *
     * Fix contact address
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if (isset($ResultSet->contacts->owner[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->address)));
            $filteredAddress = array_pad($filteredAddress, 9, '');
            $ResultSet->contacts->owner[0]->organization = $filteredAddress[0];
            $ResultSet->contacts->owner[0]->name = $filteredAddress[1];
            $ResultSet->contacts->owner[0]->city = $filteredAddress[3];
            $ResultSet->contacts->owner[0]->state = $filteredAddress[4];
            $ResultSet->contacts->owner[0]->country = $filteredAddress[5];
            $ResultSet->contacts->owner[0]->phone = str_replace('Phone: ', '', $filteredAddress[6]);
            $ResultSet->contacts->owner[0]->fax = str_replace('Fax: ', '', $filteredAddress[7]);
            $ResultSet->contacts->owner[0]->email = str_replace('E-mail: ', '', $filteredAddress[8]);
            $ResultSet->contacts->owner[0]->address = $filteredAddress[2];
        }
    }
}

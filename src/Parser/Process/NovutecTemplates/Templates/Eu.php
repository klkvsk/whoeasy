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
 * Template for .EU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Eu extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/technical:\n(.*?)(?=registrar)/is',
                                2 => '/registrar:\n(.*?)(?=name servers)/is', 3 => '/name servers:\n(.*?)(?=keys:)/is',
                                4 => '/keys:\n(.*?)(?=Please visit)/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/name:(?>[\x20\t]*)(.+)$/im'         => 'contacts:tech:name',
               '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
               '/language:(?>[\x20\t]*)(.+)$/im'     => 'contacts:tech:language',
               '/phone:(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:phone',
               '/fax:(?>[\x20\t]*)(.+)$/im'          => 'contacts:tech:fax',
               '/email:(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:email' ],
        2 => [ '/name:(?>[\x20\t]*)(.+)$/im'    => 'registrar:name',
               '/website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url' ],
        3 => [ '/\n(?>[\x20\t]+)(.+)$/im'        => 'nameserver',
               '/\n(?>[\x20\t]+)(.+) \(.+\)$/im' => 'nameserver',
               '/\n(?>[\x20\t]+).+ \((.+)\)$/im' => 'ips' ],
        4 => [ '/keyTag:(.+)$/im' => 'dnssec' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Status:(?>[\x20\t]*)AVAILABLE/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}
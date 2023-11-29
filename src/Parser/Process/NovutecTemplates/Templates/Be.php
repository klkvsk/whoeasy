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

use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\Regex;

/**
 * Template for .BE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Be extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain:(?>[\x20\t]*)(.*?)(?=registrant)/is',
                                2 => '/registrar technical contacts:\n(.*?)(?=registrar:)/is',
                                3 => '/registrar:\n(.*?)(?=nameservers)/is',
                                4 => '/nameservers:\n(.*?)(?=keys:)/is',
                                5 => '/keys:\n(.*?)(?=Please visit)/is',
                                6 => '/visit (.+)? for/is'
        ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/status:(?>[\x20\t]*)(.+)$/im'     => 'status',
               '/domain:(?>[\x20\t]*)(.+)$/im'     => 'name',
               '/Registered:(?>[\x20\t]*)(.+)$/im' => 'created' ],
        2 => [ '/name:(?>[\x20\t]*)(.+)$/im'         => 'contacts:tech:name',
               '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
               '/language:(?>[\x20\t]*)(.+)$/im'     => 'contacts:tech:language',
               '/phone:(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:phone',
               '/fax:(?>[\x20\t]*)(.+)$/im'          => 'contacts:tech:fax',
               '/email:(?>[\x20\t]*)(.+)$/im'        => 'contacts:tech:email' ],
        3 => [ '/name:(?>[\x20\t]*)(.+)$/im'    => 'registrar:name',
               '/website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url' ],
        4 => [ '/\n(?>[\x20\t]+)(.+)$/im'        => 'nameserver',
               '/\n(?>[\x20\t]+)(.+) \(.+\)$/im' => 'nameserver',
               '/\n(?>[\x20\t]+).+ \((.+)\)$/im' => 'ips' ],
        5 => [ '/keyTag:(.+)$/im' => 'dnssec' ],
        6 => [ '/visit (.+?) for$/im' => 'webserver']
    ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/Status:(?>[\x20\t]*)AVAILABLE/i';


    public function parse(Result $result, string $rawData): void
    {
        parent::parse($result, $rawData);
        if (str_contains($result->webserver ?? '', 'dnsbelgium')) {
            $abuseUrl = sprintf('https://www.dnsbelgium.be/en/contact?reason=4&domain=%s', $result->name);
            $result->addItem('contacts:abuse:email', $abuseUrl);
        }
    }
}
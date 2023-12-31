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
 * Template for .NC
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Nc extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/domain(?>[\x20\t]*):(.*?)(?=domain server)/is',
                                2 => '/domain server (.*?)(?=registrant name)/is',
                                3 => '/registrant name(?>[\x20\t]*):(.*?)$/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/created on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'      => 'created',
               '/last updated on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed',
               '/expires on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'      => 'expires' ],
        2 => [ '/domain server [0-9]{1}(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver' ],
        3 => [
            '/registrant name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'             => 'contacts:owner:organization',
            '/registrant address [0-9]{1}(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
            '/contact (first|last)name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:name' ] ];

    /**
     * RegEx to check availability of the domain name
     */
    protected ?string $available = '/No entries found/i';

    /**
     * After parsing ...
     *
     * Fix owner contact address
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $ResultSet = $WhoisParser->getResult();

        if (isset($ResultSet->contacts->owner[0]->address)) {
            if (sizeof($ResultSet->contacts->owner[0]->address) === 5) {
                $ResultSet->contacts->owner[0]->city = $ResultSet->contacts->owner[0]->address[3];
                $ResultSet->contacts->owner[0]->country = $ResultSet->contacts->owner[0]->address[4];
                $ResultSet->contacts->owner[0]->address = [
                    $ResultSet->contacts->owner[0]->address[0],
                    $ResultSet->contacts->owner[0]->address[1],
                    $ResultSet->contacts->owner[0]->address[2] ];
            } else {
                $ResultSet->contacts->owner[0]->city = $ResultSet->contacts->owner[0]->address[2];
                $ResultSet->contacts->owner[0]->address = [
                    $ResultSet->contacts->owner[0]->address[0],
                    $ResultSet->contacts->owner[0]->address[1] ];
            }
        }
    }
}
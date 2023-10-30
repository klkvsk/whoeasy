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
 * Template for ARIN
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Arin extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     */
    protected array $blocks = [ 1 => '/NetRange:(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
                                2 => '/OrgName:(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
                                3 => '/OrgTechHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
                                4 => '/OrgAbuseHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
                                5 => '/RTechHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
                                6 => '/ReferralServer:(?>[\x20\t]*)(.*?)[\r\n]{2}/is' ];

    /**
     * Items for each block
     *
     * @var array
     */
    protected array $blockItems = [
        1 => [ '/^NetRange:(?>[\x20\t]*)(.+)$/im'  => 'network:inetnum',
               '/^NetName:(?>[\x20\t]*)(.+)$/im'   => 'network:name',
               '/^NetHandle:(?>[\x20\t]*)(.+)$/im' => 'network:handle',
               '/^NetType:(?>[\x20\t]*)(.+)$/im'   => 'status',
               '/^RegDate:(?>[\x20\t]*)(.+)$/im'   => 'created',
               '/^Updated:(?>[\x20\t]*)(.+)$/im'   => 'changed' ],
        2 => [ '/^OrgId:(?>[\x20\t]*)(.+)$/im'      => 'contacts:owner:handle',
               '/^OrgName:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:organization',
               '/^Address:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:address',
               '/^City:(?>[\x20\t]*)(.+)$/im'       => 'contacts:owner:city',
               '/^StateProv:(?>[\x20\t]*)(.+)$/im'  => 'contacts:owner:state',
               '/^PostalCode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
               '/^Country:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:country',
               '/^RegDate:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:created',
               '/^Updated:(?>[\x20\t]*)(.+)$/im'    => 'contacts:owner:changed' ],
        3 => [ '/^OrgTechHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle',
               '/^OrgTechName:(?>[\x20\t]*)(.+)$/im'   => 'contacts:tech:name',
               '/^OrgTechPhone:(?>[\x20\t]*)(.+)$/im'  => 'contacts:tech:phone',
               '/^OrgTechEmail:(?>[\x20\t]*)(.+)$/im'  => 'contacts:tech:email' ],
        4 => [ '/^OrgAbuseHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:handle',
               '/^OrgAbuseName:(?>[\x20\t]*)(.+)$/im'   => 'contacts:abuse:name',
               '/^OrgAbusePhone:(?>[\x20\t]*)(.+)$/im'  => 'contacts:abuse:phone',
               '/^OrgAbuseEmail:(?>[\x20\t]*)(.+)$/im'  => 'contacts:abuse:email' ],
        5 => [ '/^RTechHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:rtech:handle',
               '/^RTechName:(?>[\x20\t]*)(.+)$/im'   => 'contacts:rtech:name',
               '/^RTechPhone:(?>[\x20\t]*)(.+)$/im'  => 'contacts:rtech:phone',
               '/^RTechEmail:(?>[\x20\t]*)(.+)$/im'  => 'contacts:rtech:email' ],
        6 => [ '/^ReferralServer:(?>[\x20\t]*)(.+)$/im' => 'referral_server' ] ];

    /**
     * After parsing do something
     *
     * If ARNIC says the organization is different change the whois server and
     * restart parsing.
     *
     * @param object $WhoisParser
     * @return void
     */
    public function postProcess(object $WhoisParser): void
    {
        $Result = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();

        foreach ($Result->contacts as $contactObject) {
            foreach ($contactObject as $contact) {
                if (isset($contact->handle) && $contact->handle === 'AFRINIC') {
                    $Result->reset();
                    $Config->setCurrent($Config->get('afrinic'));
                    $WhoisParser->call();
                }
            }
        }

        if (isset($Result->referral_server) && $Result->referral_server != '') {
            $referralServer = str_replace('whois://', '', $Result->referral_server);
            $mapping = $Config->get($referralServer);
            $Result->reset();
            $Config->setCurrent($Config->get($mapping['template']));
            $WhoisParser->call();
        }
    }
}

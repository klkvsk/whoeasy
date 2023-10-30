<?php
/** @noinspection PhpMissingFieldTypeInspection */

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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result
 */

namespace Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result;

/**
 * WhoisParser Result Contact
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Contact extends AbstractResult
{

    /**
     * Handle name
     *
     * @var string
     */
    protected $handle;

    /**
     * Handle type
     *
     * @var string
     */
    protected $type;

    /**
     * Name of person
     *
     * @var string
     */
    protected $name;

    /**
     * Name of organization
     *
     * @var string
     */
    protected $organization;

    /**
     * Email address
     *
     * @var string
     */
    protected $email;

    /**
     * Address field
     *
     * @var array
     */
    protected $address;

    /**
     * Zipcode of address
     *
     * @var string
     */
    protected $zipcode;

    /**
     * City of address
     *
     * @var string
     */
    protected $city;

    /**
     * State of address
     *
     * @var string
     */
    protected $state;

    /**
     * Country of address
     *
     * @var string
     */
    protected $country;

    /**
     * Phone number
     *
     * @var string
     */
    protected $phone;

    /**
     * Fax number
     *
     * @var string
     */
    protected $fax;

    /**
     * Created date of handle
     *
     * @var string
     */
    protected $created;

    /**
     * Last changed date of handle
     *
     * @var string
     */
    protected $changed;

}
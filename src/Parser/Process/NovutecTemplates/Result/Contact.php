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
    public $handle;

    /**
     * Handle type
     *
     * @var string
     */
    public $type;

    /**
     * Name of person
     *
     * @var string
     */
    public $name;

    /**
     * Name of organization
     *
     * @var string
     */
    public $organization;

    /**
     * Email address
     *
     * @var string
     */
    public $email;

    /**
     * Address field
     *
     * @var array
     */
    public $address;

    /**
     * Zipcode of address
     *
     * @var string
     */
    public $zipcode;

    /**
     * City of address
     *
     * @var string
     */
    public $city;

    /**
     * State of address
     *
     * @var string
     */
    public $state;

    /**
     * Country of address
     *
     * @var string
     */
    public $country;

    /**
     * Phone number
     *
     * @var string
     */
    public $phone;

    /**
     * Fax number
     *
     * @var string
     */
    public $fax;

    /**
     * Created date of handle
     *
     * @var string
     */
    public $created;

    /**
     * Last changed date of handle
     *
     * @var string
     */
    public $changed;

}
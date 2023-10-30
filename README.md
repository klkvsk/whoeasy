Whoeasy - smart WHOIS client and parser for PHP
====================

Lookup domain names, IP addresses and AS numbers by WHOIS.


Installation
------------

Install from composer:

```shell
composer install klkvsk/whoeasy
```

Usage
-----

The main `Whois` class is a factory, and provides shorthand methods.

```php
// get raw text answer
$rawText = \Klkvsk\Whoeasy\Whois::getRaw("example.com");

// or with parsing
$answer = \Klkvsk\Whoeasy\Whois::getParsed("example.com");
echo $answer->result->registrar->name;
```

You can customize the factory by extending `Whois` 
or you can utilize `WhoisClient` and `WhoisParser` directly.

Whoeasy is easily extensible. You can add your own client adapters, parsers, server configs, etc.


Whois-servers registry
-----
By default, the client will select an appropriate server for your query.
The list of servers is automatically generated from https://github.com/rfc1036/whois - 
a default `whois` tool in most Linux distributions. This is the most up-to-date source
of correct whois servers per tld.


ToDos
-----
* Querying NIC handles, IP and ASN
* Using RDAP as an alternative adapter
* Replace Novutec parsing templates with own 

3rd Party Libraries
-------------------
Parsing to a single format structure is based on Novutec WhoisParser
* https://github.com/3name/WhoisParser

Issues
------
Please report any issues via https://github.com/klkvsk/whoeasy/issues

LICENSE and COPYRIGHT
-----------------------
Copyright (c) 2023 Misha Kulakovsky (https://github.com/klkvsk)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

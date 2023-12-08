Whoeasy - smart WHOIS client and parser for PHP
====================

Lookup domain names, IP addresses and AS numbers by WHOIS.
Parse answers into structured data.
Use proxies to counter rate limits.

Installation
------------

Install from composer (until 1.0 prefer dev-master over releases, it's buggy anyway):

```shell
composer install klkvsk/whoeasy=dev-master
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

Whoeasy is easily extensible. 
You can add your own client adapters, parsers, server configs, proxy providers, etc.

Built in client adapters are:
- CurlTelnet - default if ext-curl is installed. Supports any proxies curl does.
- Socket - fallback, uses `stream_socket_client`. Supports only HTTP(s)-tunnel proxies.

Whois-servers registry
-----
By default, the client will select an appropriate server for your query.
The list of servers is automatically generated from https://github.com/rfc1036/whois - 
a default `whois` tool in most Linux distributions. This is the most up-to-date source
of correct whois servers per tld.

See [generated registry](./src/Client/Registry/GeneratedServerRegistryData.php) 
for compiled list. See [generator](./generator) for source lists and build script.

CLI tool
--------
Whoeasy can be used as command line tool:
```shell
$ vendor/bin/whoeasy -h

Usage:
  whoeasy [options] <domain>

Options:
  -s, --server <server>    use specified whois server
  -f, --format <format>    output format
  -v, --verbose            show debug output and traces
  -h, --help               show this message

Formats:
  w, raw      raw response
  t, text     clean text response (comments removed)
  r, result   structured result object [default]
  f, fields   parsed key-value pairs
  g, groups   key-value pairs split in blocks

```


ToDos
-----
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

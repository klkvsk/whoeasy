<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Parser\Data\AsnResult;
use Klkvsk\Whoeasy\Parser\Data\ContactResult;
use Klkvsk\Whoeasy\Parser\Data\DomainResult;
use Klkvsk\Whoeasy\Parser\Data\IpResult;
use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Extractor\Extractor;
use Klkvsk\Whoeasy\Parser\Extractor\GroupsExtractor;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Result\Result as NovutecResult;

class CommonStructure implements DataProcessorInterface
{
    public function __construct()
    {
    }

    public function process(WhoisAnswer $answer): void
    {
        $e = new GroupsExtractor($answer->groups);
//        echo $answer->text . "\n\n";

        switch ($answer->queryType) {
            case RequestInterface::QUERY_TYPE_DOMAIN:
                $s = new DomainResult();
                $this->domain($e, $s, $answer->server);
                $this->mergeNovutek($s, $answer->novutecResult);
                if ($s->nameservers) {
                    $s->nameservers = array_map(
                    // some include resolved ips
                        fn($ns) => preg_replace('/\s+[0-9a-f.:\s]+$/i', '', $ns),
                        $s->nameservers
                    );
                    $s->nameservers = array_map(
                    // some include statuses, comments, other additional info
                        fn($ns) => preg_replace('/\s+[[(#;|].+$/i', '', $ns),
                        $s->nameservers
                    );
                }

                if (!$s->status) {
                    if (preg_match('/(domain not found|^no.+found|nxdomain|^no match|no entries found)/i', $answer->rawData)) {
                        $s->status = 'NOT FOUND';
                    }
                }

                if ($answer->server === 'whois.denic.de') {
                    $s->status = match ($s->status) {
                        'free', 'invalid' => "NOT FOUND",
                        'connect'         => "ACTIVE",
                        'failed'          => "DISABLED",
                        default           => $s->status,
                    };
                    $s->registrar->name ??= 'DENIC eG';
                    $s->registrar->phone ??= '+4969272350';
                    $s->registrar->address ??= 'Theodor-Stern-Kai 1, 60596 Frankfurt am Main, GERMANY';
                    $s->registrar->email ??= 'info@denic.de';

                    $abuse = new ContactResult();
                    $abuse->type = 'abuse';
                    $abuse->name = 'go to www.denic.de';
                    $abuse->email = 'https://webwhois.denic.de/?lang=en&query=' . $s->name;
                    $s->contacts[] = $abuse;
                }

                if ($e->string('source') === 'AT-DOM') {
                    if (preg_match('/\s*\(\s*(http.)\s*\).*$/i', $s->registrar->name ?? '', $m)) {
                        $s->registrar->name = str_replace($m[0], '', $s->registrar->name);
                        $s->registrar->email ??= $m[1];
                    }
                }
                if ($answer->server === 'whois.kg') {
                    if (preg_match('/\nName servers.+\n\n([\s\S]+?)(\n\n|$)/i', $answer->text, $m)) {
                        $nameservers = explode("\n", $m[1]);
                        $nameservers = array_map(trim(...), $nameservers);
                        $nameservers = array_map(strtolower(...), $nameservers);
                        $s->nameservers = $nameservers;
                    }
                    if (preg_match('/^Domain (\S+)( \((.+?)\))?/', $answer->text, $m)) {
                        $s->name = strtolower($m[1]);
                        $s->status = $m[3] ?? null;
                    }
                }

                if ($answer->server === 'whois.register.bg') {
                    $s->name = preg_replace('/\s*\(\s*.+\s*\).*$/i', '', $s->name ?? '');
                    if (empty($s->contacts)) {
                        $owner = new ContactResult();
                        $owner->type = 'registrant';
                        $owner->name = 'private';
                        $owner->email = 'see whois at https://www.register.bg/';
                        $s->contacts[] = $owner;
                    }
                    if ($s->registrar->isEmpty()) {
                        $s->registrar->name = 'Register.BG Ltd.';
                        $s->registrar->email = 'hostmaster@register.bg';
                    }
                }

                if ($answer->server === 'whois.isoc.org.il') {
                    if (!$s->created) {
                        // created field is repeated resulting in some kind of history log
                        // for actual "changed" extractor took the last value
                        // here we take the first one as chronologically first
                        $changedDates = $e->field('changed');
                        $assignedDate = array_values((array)$changedDates)[0] ?? null;
                        if ($assignedDate) {
                            $s->created = $e::parseDate($assignedDate);
                        }
                    }
                }

                if (str_ends_with($answer->server, 'tonic.to')) {
                    if (!$s->nameservers) {
                        $s->nameservers = [
                            ...$e->lcarr('primary host name'),
                            ...$e->lcarr('secondary host name'),
                        ];
                        $s->status = $s->status ?: 'OK';
                        $s->registrar->name ??= 'Tonic Domains Corp.';
                        $s->registrar->address ??= 'P.O. Box 42, Pt San Quentin, CA 94964, USA';
                        $s->registrar->email ??= 'hostmaster@tonic.to';
                    }
                }
                if (str_ends_with($answer->server, 'nic.pa')) {
                    if (!$s->nameservers) {
                        $s->nameservers = [
                            ...$e->lcarr('primary dns hostname'),
                            ...$e->lcarr('secondary dns hostname'),
                        ];
                        $s->status = $s->status ?: 'OK';
                        $s->registrar->name ??= 'NIC-Panama';
                        $s->registrar->email ??= 'http://www.nic.pa/en';

                        if ($s->contacts) {
                            $s->contacts[0]->name ??= $e->string('organization');
                        }
                    }
                }
                if ($answer->server == 'whois.nic.ac.uk') {
                    $s->nameservers = [
                        ...$e->lcarr('servers'),
                    ];
                    $s->status = 'OK';
                    $s->expires = $e->date('renewal date');
                    $s->changed = $e->date('entry updated');
                    $s->registrar->name ??= $e->string('registered by');
                    $registrant = new ContactResult();
                    $registrant->name = $e->string('registrant contact');
                    $registrantAddress = $e->arr('registrant address');
                    foreach ($registrantAddress as $i => $line) {
                        if (preg_match('/^(.+) \(phone\)/i', $line, $m)) {
                            $registrant->phone = $m[1];
                            unset($registrantAddress[$i]);
                        }
                        if (str_contains($line, '@')) {
                            $registrant->email = $line;
                            unset($registrantAddress[$i]);
                        }
                    }
                    $registrant->address = implode(', ', $registrantAddress);
                    $s->contacts[] = $registrant;
                }

                if ($reseller = $e->field('Registration Service Provider')) {
                    // found in aruba via tucows
                    if (!empty($reseller)) {
                        $resellerContant = new ContactResult();
                        $resellerContant->type = 'reseller';
                        if (is_array($reseller)) {
                            $resellerContant->name = $reseller[0];
                            foreach ($reseller as $line) {
                                if (preg_match('/(https?:[^ ]+)/i', $line, $m)) {
                                    $resellerContant->address = $m[1];
                                }
                                if (preg_match('/([-a-z0-9.]+@[-a-z0-9.]+)/i', $line, $m)) {
                                    $resellerContant->email = $m[1];
                                }
                                if (preg_match('/(\+?[0-9.() -]{8,})/i', $line, $m)) {
                                    $resellerContant->phone = $m[1];
                                }
                            }
                        } else {
                            $resellerContant->name = $reseller;
                        }

                        $s->contacts[] = $resellerContant;
                    }
                }

                // empty strings to nulls in contact
                foreach ($s->contacts as $contact) {
                    if ($contact->name === '') {
                        $contact->name = null;
                    }
                    if ($contact->address === '') {
                        $contact->address = null;
                    }
                    if ($contact->phone === '') {
                        $contact->phone = null;
                    }
                    if ($contact->email === '') {
                        $contact->email = null;
                    }
                }

                // deduplicate owner and registrant in favour to owner
                foreach ($s->contacts as $i => $contact) {
                    if ($contact->type === 'owner') {
                        foreach ($s->contacts as $j => $contact2) {
                            if ($contact2->type === 'registrant') {
                                if ($contact->name === $contact2->name
                                    && $contact->email === $contact2->email
                                    && $contact->address === $contact2->address
                                    && $contact->phone === $contact2->phone
                                ) {
                                    unset($s->contacts[$j]);
                                }
                            }
                        }
                    }
                }

                break;

            case RequestInterface::QUERY_TYPE_IPV4:
            case RequestInterface::QUERY_TYPE_IPV6:
                $s = new IpResult();
                $this->ip($e, $s);
                break;

            case RequestInterface::QUERY_TYPE_ASN:
                $s = new AsnResult();
                $this->asn($e, $s);
                break;

            default:
                throw new \InvalidArgumentException($answer->queryType);
        }
        $s->type = $answer->queryType;
        $s->name ??= $answer->query;

        $answer->result = $s;
    }

    protected function domain(Extractor $e, DomainResult $s, string $whoisServer = null)
    {
        $s->name = $e->lcstring('domain*name', 'domain', 'name');
        $s->status = implode(', ', $e->arr('status', 'state', 'domain*status', 'registration*status', '*status'));
        $s->created = $e->date(
            'created', 'created*date', 'creation*date', 'created*at', 'created*on',
            'registered* on', 'registered*date', 'registration*date', 'registration*time',
            '*commencement*date', 'domain*registration*date', 'domain*creation*date',
            'registered', 'issue*date', 'record*created'
        );
        $s->changed = $e->date(
            'changed', 'last-update', 'update*date', 'updated*at',
            'last*updated', 'last*modified', 'last*update', 'modified',
            'last*update*date', 'last*update*on', 'last*edited*',
            'record*last*update*on'
        );
        $s->expires = $e->date('*expir*', 'paid-till', 'free-date', 'validity');


        $s->nameservers = $e->lcarr(
            'name*server*', 'nserver', 'ns', 'dns', 'domain*name*server', 'dns*hostnames',
            'domain*servers'
        );


        $s->refer = $e->lcstring('refer*to', 'refer', 'reg*whois*', '*whois*server');

        $s->registrar = new ContactResult();
        $eReg = $e->group('registrar*')->after('registrar*');
        $s->registrar->name = $eReg->string('registrar', '*name*', '*org*');
        $s->registrar->address = $eReg->lcstring('*address*');
        $s->registrar->email = $eReg->lcstring('*abuse*email', '*abuse*', '*email*', '*e-mail*', '*url');
        $s->registrar->phone = $eReg->lcstring('*abuse*phone', '*phone*');

        $s->contacts = [];
        foreach ([ 'registrant', 'owner', 'admin', 'tech', 'abuse' ] as $contactType) {
            $eCon = $e->group("$contactType*")->after("$contactType*");
            $contact = $this->contact($e, $eCon, $contactType);
            if ($contact->name || $contact->email || $contact->phone) {
                $s->contacts[] = $contact;
            }
        }

        if ($whoisServer === 'whois.fi') {
            $eCon = $e->group('holder*');
            $contact = $this->contact($e, $eCon, 'owner');
            $regNumber = $eCon->string('reg*number');
            if ($regNumber) {
                $contact->name .= " ($regNumber)";
            }
            $s->contacts[] = $contact;

            $s->registrar->email ??= $e->group('registrar')->lcstring('www');
        }

        if ($e->field('source') === 'TCI') {
            $contact = new ContactResult();
            $contact->type = 'registrant';
            $contact->name = $e->string('org');
            $inn = $e->string('taxpayer-id');
            if ($inn) {
                $contact->name .= " (INN $inn)";
            }
            $s->contacts[] = $contact;
        }

        if ($e->field('source') === 'FRNIC') {
            $eReg = $e->skip(1)->group('registrar');

            // data has "changed" field that is not related to domain, but to contact info.
            // force to use proper "last-update" field:
            $s->changed = $e->date('last-update');

            $s->registrar->email ??= $eReg->string('e-mail');
            $s->registrar->address ??= $eReg->string('address');
            $s->registrar->phone ??= $eReg->string('phone');

            foreach ([ 'holder-c', 'admin-c', 'tech-c' ] as $contactHandleType) {
                $contactHandle = $e->string($contactHandleType);
                if (!$contactHandle) {
                    continue;
                }
                foreach ($e->groups as $eGrp) {
                    $handle = $eGrp->string('nic-hdl');
                    if ($handle !== $contactHandle) {
                        continue;
                    }
                    if (isset($s->contacts[$handle])) {
                        continue;
                    }
                    $contact = new ContactResult();
                    $contact->type = preg_replace('/-c$/', '', $contactHandleType);
                    $contact->name = $eGrp->string('contact');
                    $contact->email = $eGrp->string('e-mail');
                    $contact->address = $eGrp->string('address');
                    $contact->phone = $eGrp->string('phone');
                    if ($contact->name || $contact->email || $contact->phone) {
                        $s->contacts[$handle] = $contact;
                    }
                    break;
                }
            }

            $s->contacts = array_values($s->contacts);
        }

        if ($s->status) {
            $s->status = preg_replace('@ https?://(www.)?icann.org[^$, ]*@', '', $s->status);
        }
    }

    public function contact(Extractor $e, Extractor $eCon, string $contactType): ?ContactResult
    {
        $contact = new ContactResult();

        $contact->type = $contactType;
        $contact->name = $eCon->string($contactType, '*name', '*org*');
        if ($contactType === 'owner') {
            // for com.br
            $ownerid = $e->string('ownerid');
            if ($ownerid) {
                $contact->name .= " ($ownerid)";
            }
        }
        $org = $eCon->string('*org*');
        if ($org && $org != $contact->name) {
            $contact->name ??= "";
            if ($contact->name) {
                $contact->name .= ", ";
            }
            $contact->name .= $org;
        }

        $contact->address =
            implode(', ', array_filter([
                $eCon->string('*postal*', '*zip*'),
                $eCon->string('*country*'),
                $eCon->string('*city*'),
                $eCon->string('*state*'),
                $eCon->string('*address*'),
            ]));

        $contact->email = $eCon->lcstring('*email', '*e-mail', '* mail', '*mailto');
        $contact->phone = $eCon->lcstring('*phone');

        return $contact;
    }

    public function mergeNovutek(DomainResult $s, NovutecResult $novutec)
    {
        $s->name ??= $novutec->name ? strtolower($novutec->name) : null;
        if (empty($s->nameservers) && !empty($novutec->nameserver)) {
            $nameservers = $novutec->nameserver;
            if (is_string($nameservers)) {
                $nameservers = preg_split('/[\n\s,; ]/', $nameservers, -1, PREG_SPLIT_NO_EMPTY);
            }
            $nameservers = array_map(trim(...), (array)$nameservers);
            $nameservers = array_map(strtolower(...), $nameservers);
            $s->nameservers = $nameservers;
        }

        if (!$s->status) {
            $status = (array)$novutec->status;
            sort($status);
            $s->status = implode(', ', (array)$novutec->status);
        }

        $s->refer ??= $novutec->whoisserver;

        $fixText = function ($t) {
            $t = implode("\n", (array)$t);
            $t = explode("\n", $t);
            $t = array_filter($t);
            $t = array_map(trim(...), $t);
            return implode(', ', $t) ?: null;
        };

        $s->registrar->name ??= $fixText($novutec->registrar->name ?? null);
        $s->registrar->phone ??= $fixText($novutec->registrar->phone ?? null);
        $s->registrar->email ??= strtolower($fixText($novutec->registrar->email ?? null) ?? '') ?: null;

        if (preg_match('/(redacted for privacy|query the rdds service)/i', $s->registrar->phone ?? '')) {
            $s->registrar->phone = null;
        }
        if (preg_match('/(redacted for privacy|query the rdds service)/i', $s->registrar->email ?? '')) {
            $s->registrar->email = null;
        }

        foreach ($novutec->contacts as $contactType => $contacts) {
            $c = null;
            $contactType = match ($contactType) {
                'owner' => 'registrant',
                default => $contactType,
            };
            foreach ($s->contacts as $sContact) {
                if ($sContact->type == $contactType) {
                    $c = $sContact;
                    break;
                }
            }
            if (!$c) {
                $c = new ContactResult();
                $c->type = $contactType;
            }
            foreach ($contacts as $contact) {
                $c->name ??= $fixText($contact->name ?? null);
                $c->email ??= strtolower($fixText($contact->email ?? null) ?: '') ?: null;
                $c->phone ??= $fixText($contact->phone ?? null);

                if (preg_match('/(redacted for privacy|query the rdds service)/i', $c->phone ?? '')) {
                    $c->phone = null;
                }
                if (preg_match('/(redacted for privacy|query the rdds service)/i', $c->email ?? '')) {
                    $c->email = null;
                }

            }
            if (!in_array($c, $s->contacts) && ($c->name || $c->phone || $c->email)) {
                $s->contacts[] = $c;
            }
        }
    }

    protected function ip(Extractor $e, IpResult|AsnResult $s)
    {
        if ($s instanceof IpResult) {
            $s->name = $e->string('netname', 'inetnum', 'netrange');
            $s->range = $e->string('route', 'inetnum', 'cidr', 'netrange');
            $s->asn = $e->string('origin-as', 'origin');
        }

        $s->created = $e->date('created', 'created*date', 'creation*date', 'created*at', 'regdate');
        $s->changed = $e->date('changed', 'update*date', 'updated*at', 'last*updated', 'last*modified',
            'last*update', 'modified', 'updated');

        $eOwn = $e->group('orgname', 'org*name', 'org', '*org*');
        $o = new ContactResult();
        $o->name = $eOwn->string('role', 'org', 'org*name') ?: $e->string('descr');
        $o->address =
            implode(', ', array_filter([
                $eOwn->string('*postal*', '*zip*'),
                $eOwn->string('*country*'),
                $eOwn->string('*city*'),
                $eOwn->string('*state*'),
                $eOwn->string('*address*'),
            ]))
                ?: $e->string('*address*');

        $o->email = $eOwn->string('*mail*') ?: $e->string('*abuse*mail*', '*mail*');
        $o->phone = $eOwn->string('*phone*') ?: $e->string('*phone*');
        $s->owner = $o;

        $s->contacts = [];
        foreach ($e->groups as $group) {
            $firstField = array_key_first($group->fields);
            if (preg_match('/org(.+)(name|handle)/i', $firstField, $m)) {
                $c = new ContactResult();
                $c->type = $m[1];
                $c->name = $group->field("org{$c->type}name");
                $c->email = $group->field("org{$c->type}email");
                $c->phone = $group->field("org{$c->type}phone");
                $s->contacts[$c->type] = $c;
            }
        }
        $s->contacts = array_values($s->contacts);
    }

    protected function asn(GroupsExtractor $e, AsnResult $s)
    {
        $this->ip($e, $s);
        $s->name = $e->string('as*name', 'aut*num');
        $s->range = $e->string('as*block', 'aut*num');
        $s->asn = $e->string('aut*num', 'as*number', 'as', 'asn');
    }

}
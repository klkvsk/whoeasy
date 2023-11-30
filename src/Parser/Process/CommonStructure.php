<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Client\RequestInterface;
use Klkvsk\Whoeasy\Client\ResponseInterface;
use Klkvsk\Whoeasy\Parser\Data\AbstractResult;
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
        //echo $answer->text . "\n\n";

        switch ($answer->queryType) {
            case RequestInterface::QUERY_TYPE_DOMAIN:
                $s = new DomainResult();
                $this->domain($e, $s);

                if ($answer->novutecResult instanceof NovutecResult) {
                    $this->mergeNovutek($s, $answer->novutecResult);
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

    protected function domain(Extractor $e, DomainResult $s)
    {
        $s->name = $e->lcstring('domain*name', 'domain', 'name');
        $s->status = $e->string('status', 'state', 'domain*status');
        $s->created = $e->date(
            'created', 'created*date', 'creation*date', 'created*at',
            'registered* on', 'registration*date', 'registration*time',
            '*commencement*date', 'domain*registration*date', 'domain*creation*date',
            'registered',
        );
        $s->changed = $e->date(
            'changed', 'update*date', 'updated*at',
            'last*updated', 'last*modified', 'last*update', 'modified'
        );
        $s->expires = $e->date('*expir*', 'paid-till', 'free-date');


        $s->nameservers = $e->lcarr(
            'name*server*', 'nserver', 'ns', 'dns', 'domain*name*server'
        );

        $s->registrar = new ContactResult();
        $s->registrar->type = 'registrar';
        $eReg = $e->group('registrar*')->after('registrar*');
        $s->registrar->name = $eReg->string('registrar', '*name*', '*org*');
        $s->registrar->email = $eReg->lcstring('*abuse*email', '*abuse*', '*email*');
        $s->registrar->phone = $eReg->lcstring('*abuse*phone', '*phone*');

        $s->contacts = [];
        foreach ([ 'registrant', 'owner', 'admin', 'tech', 'abuse' ] as $contactType) {
            $eCon = $e->group("$contactType*")->after("$contactType*");
            $contact = new ContactResult();

            $contact->type = $contactType;
            $contact->name = $eCon->string($contactType, '*name', '*org*');
            $org = $eCon->string('*org*');
            if ($org && $org != $contact->name) {
                $contact->name ??= "";
                if ($contact->name) {
                    $contact->name .= ", ";
                }
                $contact->name .= $org;
            }
            $contact->email = $eCon->lcstring('*email');
            $contact->phone = $eCon->lcstring('*phone');

            if ($contact->name || $contact->email || $contact->phone) {
                $s->contacts[] = $contact;
            }
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

        if ($s->status) {
            $s->status = preg_replace('@ https://icann.org[^$, ]*@', '', $s->status);
        }
    }

    public function mergeNovutek(DomainResult $s, NovutecResult $novutec)
    {
        $s->name ??= $novutec->name ? strtolower($novutec->name) : null;
        if (!isset($s->nameservers) && isset($novutec->nameserver)) {
            $nameservers = $novutec->nameserver;
            if (is_string($nameservers)) {
                $nameservers = preg_split('/[\n\s,; ]/', $nameservers, -1, PREG_SPLIT_NO_EMPTY);
            }
            $nameservers = array_map(trim(...), (array)$nameservers);
            $nameservers = array_map(strtolower(...), $nameservers);
            $s->nameservers = $nameservers;
        }
        $s->status ??= implode(', ', $novutec->status);

        if ($novutec->registrar) {
            if (preg_match('/(redacted for privacy|query the rdds service)/i', $novutec->registrar->phone ?? '')) {
                $novutec->registrar->phone = null;
            }
            if (preg_match('/(redacted for privacy|query the rdds service)/i', $novutec->registrar->email ?? '')) {
                $novutec->registrar->email = null;
            }
        }

        $s->registrar->name ??= $novutec->registrar->name ?? null;
        $s->registrar->phone ??= $novutec->registrar->phone ?? null;
        $s->registrar->email ??= $novutec->registrar->email ?? null;

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
                if (preg_match('/(redacted for privacy|query the rdds service)/i', $contact->phone ?? '')) {
                    $contact->phone = null;
                }
                if (preg_match('/(redacted for privacy|query the rdds service)/i', $contact->email ?? '')) {
                    $contact->email = null;
                }

                $c->name ??= $contact?->name ? trim($contact->name) : null;
                $c->email ??= $contact?->email ? trim($contact->email) : null;
                $c->phone ??= $contact?->phone ? trim($contact->phone) : null;
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
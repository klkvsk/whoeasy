<?php

namespace Klkvsk\Whoeasy\Parser\Process;

use Klkvsk\Whoeasy\Parser\Data\WhoisAnswer;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Standard;
use Klkvsk\Whoeasy\Parser\Process\NovutecTemplates\Templates\Type\AbstractTemplate;

class NovutecTemplates implements DataProcessorInterface
{
    public function process(WhoisAnswer $answer): void
    {
        $handler = $this->createTemplate($answer->server, $answer->query);
        $result = new NovutecTemplates\Result\Result();
        $rawData = $handler->translateRawData($answer->rawData);
        $handler->parse($result, $rawData);
        $answer->result = $result;
    }

    protected function createTemplate(?string $server, ?string $query): AbstractTemplate
    {
        $templates = $this->templates[$server] ?? null;
        if (!$templates) {
            return new Standard();
        }

        if ($query) {
            foreach ($templates as $toplevel => $template) {
                if (str_ends_with($query, $toplevel)) {
                    return new $template();
                }
            }
        }

        $template = $templates['*'];
        return new $template();
    }

    protected array $templates = [
        /** @generator-begin=novutec */
        "whois.iana.org"                 => [
            "*" => NovutecTemplates\Templates\Iana::class,
        ],
        "whois.afrinic.net"              => [
            "*" => NovutecTemplates\Templates\Afrinic::class,
        ],
        "whois.apnic.net"                => [
            "*" => NovutecTemplates\Templates\Apnic::class,
        ],
        "whois.arin.net"                 => [
            "*" => NovutecTemplates\Templates\Arin::class,
        ],
        "whois.krnic.net"                => [
            "*" => NovutecTemplates\Templates\Krnic::class,
        ],
        "whois.lacnic.net"               => [
            "*" => NovutecTemplates\Templates\Lacnic::class,
        ],
        "whois.ripe.net"                 => [
            "*" => NovutecTemplates\Templates\Ripe::class,
        ],
        "http:\/\/www.nic.ac\/"          => [
            "*" => NovutecTemplates\Templates\Icb::class,
        ],
        "whois.aeda.net.ae"              => [
            "*" => NovutecTemplates\Templates\Ae::class,
        ],
        "whois.aero"                     => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.coccaregistry.net"        => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.ag"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.agency"               => [
            "*" => NovutecTemplates\Templates\Agency::class,
        ],
        "whois.ai"                       => [
            "*" => NovutecTemplates\Templates\Ai::class,
        ],
        "whois.amnic.net"                => [
            "*" => NovutecTemplates\Templates\Am::class,
        ],
        "whois.nic.as"                   => [
            "*" => NovutecTemplates\Templates\Asnic::class,
        ],
        "whois.nic.asia"                 => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.at"                   => [
            "*" => NovutecTemplates\Templates\At::class,
        ],
        "whois.audns.net.au"             => [
            "*" => NovutecTemplates\Templates\Au::class,
        ],
        "whois.ax"                       => [
            "*" => NovutecTemplates\Templates\Ax::class,
        ],
        "whois.dns.be"                   => [
            "*" => NovutecTemplates\Templates\Be::class,
        ],
        "whois.register.bg"              => [
            "*" => NovutecTemplates\Templates\Bg::class,
        ],
        "whois1.nic.bi"                  => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.biz"                      => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "whois.nic.bo"                   => [
            "*" => NovutecTemplates\Templates\Bo::class,
        ],
        "whois.registro.br"              => [
            "*" => NovutecTemplates\Templates\Br::class,
        ],
        "whois.nic.buzz"                 => [
            "*" => NovutecTemplates\Templates\Buzz::class,
        ],
        "whois.cctld.by"                 => [
            "*" => NovutecTemplates\Templates\By::class,
        ],
        "whois2.afilias-grs.net"         => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.cira.ca"                  => [
            "*" => NovutecTemplates\Templates\Ca::class,
        ],
        "whois.cat"                      => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "ccwhois.verisign-grs.com"       => [
            "*" => NovutecTemplates\Templates\Verisign::class,
        ],
        "whois.nic.cd"                   => [
            "*" => NovutecTemplates\Templates\Cd::class,
        ],
        "whois.nic.ch"                   => [
            "*" => NovutecTemplates\Templates\Switchnic::class,
        ],
        "whois.nic.ck"                   => [
            "*" => NovutecTemplates\Templates\Ck::class,
        ],
        "whois.nic.club"                 => [
            "*" => NovutecTemplates\Templates\Club::class,
        ],
        "netcom.cm"                      => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.cnnic.cn"                 => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.co"                   => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "whois.co.nl"                    => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.co.no"                    => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.verisign-grs.com"         => [
            "*" => NovutecTemplates\Templates\Verisign::class,
        ],
        "whois.centralnic.com"           => [
            "centralnic" => NovutecTemplates\Templates\Afilias::class,
            "com.de"     => NovutecTemplates\Templates\De::class,
            "*"          => NovutecTemplates\Templates\De::class,
        ],
        "whois.ua"                       => [
            "*" => NovutecTemplates\Templates\Comua::class,
        ],
        "whois.nic.coop"                 => [
            "*" => NovutecTemplates\Templates\Coop::class,
        ],
        "whois.nic.cx"                   => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.nic.cz"                   => [
            "*" => NovutecTemplates\Templates\Cz::class,
        ],
        "whois.dk-hostmaster.dk"         => [
            "*" => NovutecTemplates\Templates\Dk::class,
        ],
        "whois.nic.dm"                   => [
            "*" => NovutecTemplates\Templates\Dm::class,
        ],
        "whois.nic.dz"                   => [
            "*" => NovutecTemplates\Templates\Dz::class,
        ],
        "whois.nic.ec"                   => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.educause.edu"             => [
            "*" => NovutecTemplates\Templates\Edu::class,
        ],
        "whois.tld.ee"                   => [
            "*" => NovutecTemplates\Templates\Ee::class,
        ],
        "whois.nic.es"                   => [
            "*" => NovutecTemplates\Templates\Es::class,
        ],
        "whois.eu"                       => [
            "*" => NovutecTemplates\Templates\Eu::class,
        ],
        "whois.fi"                       => [
            "*" => NovutecTemplates\Templates\Fi::class,
        ],
        "whois.usp.ac.fj"                => [
            "*" => NovutecTemplates\Templates\Fj::class,
        ],
        "whois.nic.fm"                   => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.nic.fo"                   => [
            "*" => NovutecTemplates\Templates\Fo::class,
        ],
        "whois.afnic.fr"                 => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "whois.adamsnames.com"           => [
            "*" => NovutecTemplates\Templates\Adamsnames::class,
        ],
        "whois.gg"                       => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.nic.gl"                   => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.hkirc.hk"                 => [
            "*" => NovutecTemplates\Templates\Hk::class,
        ],
        "whois.registry.hm"              => [
            "*" => NovutecTemplates\Templates\Hm::class,
        ],
        "hu"                             => [
            "*" => NovutecTemplates\Templates\Hu::class,
        ],
        "whois.pandi.or.id"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.domainregistry.ie"        => [
            "*" => NovutecTemplates\Templates\Ie::class,
        ],
        "whois.isoc.org.il"              => [
            "*" => NovutecTemplates\Templates\Il::class,
        ],
        "whois.nic.im"                   => [
            "*" => NovutecTemplates\Templates\Im::class,
        ],
        "whois.inregistry.net"           => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.afilias.net"              => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.iana.orgd"                => [
            "*" => NovutecTemplates\Templates\Int_::class,
        ],
        "http:\/\/www.nic.io\/"          => [
            "*" => NovutecTemplates\Templates\Io::class,
        ],
        "whois.cmc.iq"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.ir"                   => [
            "*" => NovutecTemplates\Templates\Ir::class,
        ],
        "whois.isnic.is"                 => [
            "*" => NovutecTemplates\Templates\Is::class,
        ],
        "whois.nic.it"                   => [
            "*" => NovutecTemplates\Templates\It::class,
        ],
        "whois.je"                       => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "jobswhois.verisign-grs.com"     => [
            "*" => NovutecTemplates\Templates\Verisign::class,
        ],
        "whois.jprs.jp"                  => [
            "*" => NovutecTemplates\Templates\Jp::class,
        ],
        "whois.kenic.or.ke"              => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.domain.kg"                => [
            "*" => NovutecTemplates\Templates\Kg::class,
        ],
        "whois.kr"                       => [
            "*" => NovutecTemplates\Templates\Kr::class,
        ],
        "whois.nic.kz"                   => [
            "*" => NovutecTemplates\Templates\Kz::class,
        ],
        "whois.nic.la"                   => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.nic.link"                 => [
            "*" => NovutecTemplates\Templates\Link::class,
        ],
        "whois.domreg.lt"                => [
            "*" => NovutecTemplates\Templates\Lt::class,
        ],
        "whois.dns.lu"                   => [
            "*" => NovutecTemplates\Templates\Lu::class,
        ],
        "whois.nic.lv"                   => [
            "*" => NovutecTemplates\Templates\Lv::class,
        ],
        "whois.nic.ly"                   => [
            "*" => NovutecTemplates\Templates\Ly::class,
        ],
        "whois.nic.md"                   => [
            "*" => NovutecTemplates\Templates\Md::class,
        ],
        "whois.nic.me"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.mg"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.dotmobiregistry.net"      => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.ms"                   => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.museum"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.mx"                       => [
            "*" => NovutecTemplates\Templates\Mx::class,
        ],
        "whois.na-nic.com.na"            => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.name"                 => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nc"                       => [
            "*" => NovutecTemplates\Templates\Nc::class,
        ],
        "whois.nic.nyc"                  => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "whois.nic.net.ng"               => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.domain-registry.nl"       => [
            "*" => NovutecTemplates\Templates\Nl::class,
        ],
        "whois.srs.net.nz"               => [
            "*" => NovutecTemplates\Templates\Nz::class,
        ],
        "whois.iis.nu"                   => [
            "*" => NovutecTemplates\Templates\Nu::class,
        ],
        "whois.registry.om"              => [
            "*" => NovutecTemplates\Templates\Om::class,
        ],
        "whois.pir.org"                  => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "kero.yachay.pe"                 => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.dns.pl"                   => [
            "*" => NovutecTemplates\Templates\Pl::class,
        ],
        "whois.nic.pm"                   => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "whois.nic.pr"                   => [
            "*" => NovutecTemplates\Templates\Pr::class,
        ],
        "whois.pnina.ps"                 => [
            "*" => NovutecTemplates\Templates\Cocca::class,
        ],
        "whois.dns.pt"                   => [
            "*" => NovutecTemplates\Templates\Pt::class,
        ],
        "whois.nic.pw"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.registry.qa"              => [
            "*" => NovutecTemplates\Templates\Qa::class,
        ],
        "whois.nic.re"                   => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "whois.rotld.ro"                 => [
            "*" => NovutecTemplates\Templates\Ro::class,
        ],
        "whois.rnids.rs"                 => [
            "*" => NovutecTemplates\Templates\Rs::class,
        ],
        "whois.iis.se"                   => [
            "*" => NovutecTemplates\Templates\Se::class,
        ],
        "whois.sgnic.sg"                 => [
            "*" => NovutecTemplates\Templates\Sg::class,
        ],
        "http:\/\/www.nic.sh\/"          => [
            "*" => NovutecTemplates\Templates\Icb::class,
        ],
        "whois.sk-nic.sk"                => [
            "*" => NovutecTemplates\Templates\Sk::class,
        ],
        "whois.nic.sm"                   => [
            "*" => NovutecTemplates\Templates\Sm::class,
        ],
        "whois.nic.so"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.st"                   => [
            "*" => NovutecTemplates\Templates\St::class,
        ],
        "whois.tcinet.ru"                => [
            "xn--p1ai" => NovutecTemplates\Templates\Gtld_rf::class,
            "su"       => NovutecTemplates\Templates\Su::class,
            "*"        => NovutecTemplates\Templates\Su::class,
        ],
        "whois.nic.support"              => [
            "*" => NovutecTemplates\Templates\Support::class,
        ],
        "whois.sx"                       => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.tld.sy"                   => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.tel"                  => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "whois.nic.tf"                   => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "whois.thnic.co.th"              => [
            "*" => NovutecTemplates\Templates\Th::class,
        ],
        "whois.dot.tk"                   => [
            "*" => NovutecTemplates\Templates\Tk::class,
        ],
        "http:\/\/www.nic.tm\/"          => [
            "*" => NovutecTemplates\Templates\Icb::class,
        ],
        "whois.ati.tn"                   => [
            "*" => NovutecTemplates\Templates\Tn::class,
        ],
        "whois.nic.tr"                   => [
            "*" => NovutecTemplates\Templates\Tr::class,
        ],
        "whois.nic.travel"               => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "tvwhois.verisign-grs.com"       => [
            "*" => NovutecTemplates\Templates\Tv::class,
        ],
        "whois.twnic.net.tw"             => [
            "*" => NovutecTemplates\Templates\Tw::class,
        ],
        "whois.tznic.or.tz"              => [
            "*" => NovutecTemplates\Templates\Ee::class,
        ],
        "whois.co.ug"                    => [
            "*" => NovutecTemplates\Templates\Ug::class,
        ],
        "whois.nic.uk"                   => [
            "*" => NovutecTemplates\Templates\Uk::class,
        ],
        "whois.nic.us"                   => [
            "*" => NovutecTemplates\Templates\Neustar::class,
        ],
        "whois.nic.org.uy"               => [
            "*" => NovutecTemplates\Templates\Uy::class,
        ],
        "whois.nic.ve"                   => [
            "*" => NovutecTemplates\Templates\Ve::class,
        ],
        "vunic.vu"                       => [
            "*" => NovutecTemplates\Templates\Vu::class,
        ],
        "whois.nic.wf"                   => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "whois.website.ws"               => [
            "*" => NovutecTemplates\Templates\Ws::class,
        ],
        "xn--80ap21a"                    => [
            "*" => NovutecTemplates\Templates\Kz::class,
        ],
        "cwhois.cnnic.cn"                => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.xxx"                  => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.nic.yt"                   => [
            "*" => NovutecTemplates\Templates\Afnic::class,
        ],
        "http:\/\/whois.venez.fr\/"      => [
            "*" => NovutecTemplates\Templates\Venez::class,
        ],
        "grs-whois.hichina.com"          => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.007names.com"             => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.1api.net"                 => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.123-reg.co.uk"            => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.above.com"                => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.afternic.com"             => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.allearthdomains.com"      => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.antagus.de"               => [
            "*" => NovutecTemplates\Templates\Gtld_vautron::class,
        ],
        "whois.apisrs.com"               => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.ascio.com"                => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.biglizarddomains.com"     => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.bizcn.com"                => [
            "*" => NovutecTemplates\Templates\Gtld_xinnet::class,
        ],
        "whois.blacknight.com"           => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.columbianames.com"        => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.communigal.net"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.corehub.net"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.corenic.net"              => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.corporatedomains.com"     => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.cps-datensysteme.de"      => [
            "*" => NovutecTemplates\Templates\Gtld_cpsdatensysteme::class,
        ],
        "whois.cronon.net"               => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.directnic.com"            => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.discount-domain.com"      => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.domainarmada.com"         => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.domaincomesaround.com"    => [
            "*" => NovutecTemplates\Templates\Standardliar::class,
        ],
        "whois.domrobot.com"             => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois2.domain.com"              => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.domain.com"               => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.domainprocessor.com"      => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.domainsite.com"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.domainsoftheworld.net"    => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.domainyeti.com"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.dreamhost.com"            => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.dynadot.com"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.dyndns.com"               => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.easyspace.com"            => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.encirca.com"              => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.enom.com"                 => [
            "*" => NovutecTemplates\Templates\Gtld_enom::class,
        ],
        "whois.enterprice.net"           => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.eunamesoregon.com"        => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.eurodns.com"              => [
            "*" => NovutecTemplates\Templates\Standardliar::class,
        ],
        "whois.euturbo.com"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.fabulous.com"             => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.fastdomain.com"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.findyouadomain.com"       => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.gandi.net"                => [
            "*" => NovutecTemplates\Templates\Gtld_gandi::class,
        ],
        "whois.gochinadomains.com"       => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.godaddy.com"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.godomaingo.com"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.inname.net"               => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.instra.net"               => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.interdomain.net"          => [
            "*" => NovutecTemplates\Templates\Gtld_melbourneit::class,
        ],
        "whois.internet.bs"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.joker.com"                => [
            "*" => NovutecTemplates\Templates\Gtld_joker::class,
        ],
        "whois.markmonitor.com"          => [
            "*" => NovutecTemplates\Templates\Gtld_markmonitor::class,
        ],
        "whois.melbourneit.com"          => [
            "*" => NovutecTemplates\Templates\Gtld_melbourneit::class,
        ],
        "whois.misk.com"                 => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.moniker.com"              => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.name.com"                 => [
            "*" => NovutecTemplates\Templates\Gtld_name::class,
        ],
        "whois.namebay.com"              => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.namecheap.com"            => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.nameemperor.com"          => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.names4ever.com"           => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.namesbeyond.com"          => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.namesecure.com"           => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.namesilo.com"             => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.net-chinese.com.tw"       => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.networksolutions.com"     => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.nicproxy.com"             => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.novutec.com"              => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.ovh.com"                  => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.paycenter.com.cn"         => [
            "*" => NovutecTemplates\Templates\Gtld_xinnet::class,
        ],
        "whois.pheenix.com"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.planetdomain.com"         => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.plisk.com"                => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.pocketdomain.com"         => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.protondomains.com"        => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.psi-usa.info"             => [
            "*" => NovutecTemplates\Templates\Gtld_psiusa::class,
        ],
        "whois.publicdomainregistry.com" => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.puredomain.com"           => [
            "*" => NovutecTemplates\Templates\Gtld_variomedia::class,
        ],
        "whois.register.com"             => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.registrar.telekom.de"     => [
            "*" => NovutecTemplates\Templates\Gtld_deutschetelekom::class,
        ],
        "whois.registrygate.com"         => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.regtime.net"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.regtons.com"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.rrpproxy.net"             => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.schlund.info"             => [
            "*" => NovutecTemplates\Templates\Gtld_schlund::class,
        ],
        "whois.skykomishdomains.com"     => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.srsplus.com"              => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.subreg.cz"                => [
            "*" => NovutecTemplates\Templates\Afilias::class,
        ],
        "whois.tirupatidomains.in"       => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.totalregistrations.com"   => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.tucows.com"               => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.udag.net"                 => [
            "*" => NovutecTemplates\Templates\Gtld_rrpproxy::class,
        ],
        "whois.udomainname.com"          => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.uniregistrar.com"         => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.uniregistrar.net"         => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.webmasters.com"           => [
            "*" => NovutecTemplates\Templates\Gtld_networksolutions::class,
        ],
        "whois.webnames.ru"              => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.wildwestdomains.com"      => [
            "*" => NovutecTemplates\Templates\Gtld_godaddy::class,
        ],
        "whois.yesnic.com"               => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        "whois.your-server.de"           => [
            "*" => NovutecTemplates\Templates\Gtld_hetzner::class,
        ],
        "whois.yourjungle.com"           => [
            "*" => NovutecTemplates\Templates\Standard::class,
        ],
        /** @generator-end=novutec */
    ];

}
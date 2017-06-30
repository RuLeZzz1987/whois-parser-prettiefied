const parser = require('parse-whois');
const whois = require('node-whois');

module.exports = {
    lookup(domain) {
        return new Promise((ok, fail) => {
            whois.lookup(domain, (err, data) => {
                if (err) {
                    return fail(err);
                }

                return ok(data);
            })
        })
    },

    getWhois(domain) {
        return this.lookup(domain)
            .then(whoisInfo => parser.parseWhoIsData(whoisInfo))
            .then(whoisInfo => whoisInfo.reduce((info, entry) => {
                const {attribute, value} = entry;
                if (attribute.includes('Domain Name')) {
                    info.domainName = value;
                }
                if (attribute.includes('Registry Domain ID')) {
                    info.registryDomainId = value;
                }
                if (attribute.includes('Registrar')) {
                    if (info.registrar) {

                    } else {
                        info.registrar = {

                        }
                    }
                }

            }, {}))
    }
};

/*
* [ { attribute: 'Domain Name', value: 'ANNADUKA.COM' },
 { attribute: 'Registry Domain ID',
 value: '1819702935_DOMAIN_COM-VRSN' },
 { attribute: 'Registrar WHOIS Server',
 value: 'whois.publicdomainregistry.com' },
 { attribute: 'Registrar URL',
 value: 'www.publicdomainregistry.com' },
 { attribute: 'Updated Date', value: '2016-07-20T15:21:59Z' },
 { attribute: 'Creation Date', value: '2013-08-04T15:41:55Z' },
 { attribute: 'Registrar Registration Expiration Date',
 value: '2017-08-04T15:41:55Z' },
 { attribute: 'Registrar',
 value: 'PDR Ltd. d/b/a PublicDomainRegistry.com' },
 { attribute: 'Registrar IANA ID', value: '303' },
 { attribute: 'Domain Status',
 value: 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited' },
 { attribute: 'Registry Registrant ID',
 value: 'Not Available From Registry' },
 { attribute: 'Registrant Name', value: 'Duka Anna Viktorovna' },
 { attribute: 'Registrant Organization', value: 'none' },
 { attribute: 'Registrant Street',
 value: 'ul.Tobolskaia 31-a kv 9' },
 { attribute: 'Registrant City', value: 'Kharkov' },
 { attribute: 'Registrant State/Province', value: '' },
 { attribute: 'Registrant Postal Code', value: '61045' },
 { attribute: 'Registrant Country', value: 'UA' },
 { attribute: 'Registrant Phone', value: '+380.971922060' },
 { attribute: 'Registrant Phone Ext', value: '' },
 { attribute: 'Registrant Fax', value: '' },
 { attribute: 'Registrant Fax Ext', value: '' },
 { attribute: 'Registrant Email', value: 'dia@list.ru' },
 { attribute: 'Registry Admin ID',
 value: 'Not Available From Registry' },
 { attribute: 'Admin Name', value: 'Duka Anna Viktorovna' },
 { attribute: 'Admin Organization', value: 'none' },
 { attribute: 'Admin Street', value: 'ul.Tobolskaia 31-a kv 9' },
 { attribute: 'Admin City', value: 'Kharkov' },
 { attribute: 'Admin State/Province', value: '' },
 { attribute: 'Admin Postal Code', value: '61045' },
 { attribute: 'Admin Country', value: 'UA' },
 { attribute: 'Admin Phone', value: '+380.971922060' },
 { attribute: 'Admin Phone Ext', value: '' },
 { attribute: 'Admin Fax', value: '' },
 { attribute: 'Admin Fax Ext', value: '' },
 { attribute: 'Admin Email', value: 'dia@list.ru' },
 { attribute: 'Registry Tech ID',
 value: 'Not Available From Registry' },
 { attribute: 'Tech Name', value: 'NIC.UA Hostmaster' },
 { attribute: 'Tech Organization', value: 'NIC.UA LLC' },
 { attribute: 'Tech Street', value: 'PO BOX 147' },
 { attribute: 'Tech City', value: 'KYIV' },
 { attribute: 'Tech State/Province', value: 'KYIV' },
 { attribute: 'Tech Postal Code', value: '04050' },
 { attribute: 'Tech Country', value: 'UA' },
 { attribute: 'Tech Phone', value: '+380.442329962' },
 { attribute: 'Tech Phone Ext', value: '' },
 { attribute: 'Tech Fax', value: '+380.445937569' },
 { attribute: 'Tech Fax Ext', value: '' },
 { attribute: 'Tech Email', value: 'support@nic.ua' },
 { attribute: 'Name Server', value: 'ns10.uadns.com' },
 { attribute: 'Name Server', value: 'ns11.uadns.com' },
 { attribute: 'Name Server', value: 'ns12.uadns.com' },
 { attribute: 'Registrar Abuse Contact Email',
 value: 'abuse-contact@publicdomainregistry.com' },
 { attribute: 'Registrar Abuse Contact Phone',
 value: '+1.2013775952' },
 { attribute: 'URL of the ICANN WHOIS Data Problem Reporting System',
 value: 'http://wdprs.internic.net/' },
 { attribute: '>>> Last update of WHOIS database',
 value: '2017-06-30T11:43:18Z <<<' },
 { attribute: 'Registration Service Provided By',
 value: 'NIC.UA LLC' },
 { attribute: 'circumstances will you use this data to',
 value: '' },
 { attribute: 'End Text',
 value: 'DNSSEC:Unsigned\nFor more information on Whois status codes, please visit https://icann.org/epp\nThe data in this whois database is provided to you for information purposes\nonly, that is, to assist you in obtaining information about or related to a\ndomain name registration record. We make this information available "as is",\nand do not guarantee its accuracy. By submitting a whois query, you agree\nthat you will use this data only for lawful purposes and that, under no\n(1) enable high volume, automated, electronic processes that stress or load\nthis whois database system providing you this information; or\n(2) allow, enable, or otherwise support the transmission of mass unsolicited,\ncommercial advertising or solicitations via direct mail, electronic mail, or\nby telephone.\nThe compilation, repackaging, dissemination or other use of this data is\nexpressly prohibited without prior written consent from us. The Registrar of\nrecord is PDR Ltd. d/b/a PublicDomainRegistry.com.\nWe reserve the right to modify these terms at any time.\nBy submitting this query, you agree to abide by these terms.\n' } ]

 *
* */
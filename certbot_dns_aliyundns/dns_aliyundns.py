"""DNS Authenticator for Aliyun DNS."""
import logging
import json

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

from aliyunsdkcore.client import AcsClient
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest import DeleteDomainRecordRequest

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://ak-console.aliyun.com'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Aliyun DNS

    This Authenticator uses the Aliyun DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Aliyun DNS).'
    ttl = 600

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Aliyun DNS credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Aliyun DNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Aliyun DNS credentials INI file',
            {
                'access-key': 'AccessKey for Aliyun DNS, obtained from {0}'.format(ACCOUNT_URL),
                'access-key-secret': 'AccessKeySecret for Aliyun DNS, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_aliyundns_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_aliyundns_client().del_txt_record(domain, validation_name, validation)

    def _get_aliyundns_client(self):
        return _AliyunDNSClient(self.credentials.conf('access-key'), self.credentials.conf('access-key-secret'))


class _AliyunDNSClient():
    """
    Encapsulates all communication with the Aliyun DNS Serivce.
    """

    def __init__(self, access_key, access_key_secret):
        self._client = AcsClient(access_key, access_key_secret)


    def _find_domain_record_id(self, domain, rr = '', typ = '', value = ''):
        request = DescribeDomainRecordsRequest()
        request.set_accept_format("json")

        request.set_DomainName(domain)
        request.set_TypeKeyWord(typ)
        request.set_RRKeyWord(rr)
        request.set_ValueKeyWord(value)

        records = json.loads(self._client.do_action_with_exception(request))

        for record in records['DomainRecords']['Record']:
            if record['RR'] == rr:
                return record['RecordId']
        raise errors.PluginError('Unexpected error determining record identifier for {0}: {1}'
                                 .format(rr, 'record not found'))

    def add_txt_record(self, domain, record_name, record_value, ttl):
        rr = record_name[:record_name.rindex('.' + domain)]

        request = AddDomainRecordRequest()
        request.set_accept_format("json")

        request.set_DomainName(domain)
        request.set_Type("TXT")
        request.set_RR(rr)
        request.set_Value(record_value)
        request.set_TTL(ttl)

        self._client.do_action_with_exception(request)

    def del_txt_record(self, domain, record_name, value):
        rr = record_name[:record_name.rindex('.' + domain)]
        record_id = self._find_domain_record_id(domain, rr=rr, typ='TXT')

        request = DeleteDomainRecordRequest()
        request.set_accept_format("json")

        request.set_RecordId(record_id)

        self._client.do_action_with_exception(request)

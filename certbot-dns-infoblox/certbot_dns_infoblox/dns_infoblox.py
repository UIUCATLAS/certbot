"""DNS Authenticator for Infoblox."""
import logging

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS  Authenticator for Infoblox

    This Authenticator uses the Infoblox API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Infoblox for DNS).'
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Infoblox credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Infoblox API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Infoblox credentials INI file',
            {
                'username': 'Infoblox username',
                'password': 'Infoblox password',
                'url':      'Infoblox service URL'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_infoblox_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_infoblox_client().del_txt_record(domain, validation_name, validation)

    def _get_infoblox_client(self):
        return _InfobloxClient(self.credentials.conf('username'), self.credentials.conf('password'), self.credentials.conf('url'))


class _InfobloxClient(object):
    """
    Encapsulates all communication with the Infoblox API.
    """

    def __init__(self, username, password, url):
        self.ib = Infoblox.Infoblox(username, password, url)
        self.contenttype = 'json'
        self.req = requests.Session()
        self.url = url
        self.req.auth = requests.auth.HTTPBasicAuth(username, password)

	"""
	Magic method for calling Infoblox's API.
	"""

    def __getattr__(self, command):
		
		Commands = {

        if command in Commands:
            command = Commands[command]

        def wrapper(parameters, method='get'):
            if method == 'get':
                parameters['_return_type'] = self.contenttype
                res = self.req.get(self.baseurl + command, params=parameters)
            elif method == 'post':
                res = self.req.post(self.baseurl + command, data=json.dumps(parameters))
            elif method == 'put':
                res = self.req.post(self.baseurl + command, params=parameters)
            elif method == 'delete': # parameters is really just a ref variable
                res = self.req.delete(self.baseurl + parameters)
            else:
                return False # should we just throw an exception?
            return res.json()
        return wrapper

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain of the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Infoblox API
        """

        data = {'name': record_name,
                'text': record_content,
                'ttl': record_ttl,
				'use_ttl': true}

        try:
            logger.debug('Attempting to add record to zone %s: %s', zone_id, data)
            record_id = self.recordtxt('post', parameters=data)
        except e:
            logger.error('Encountered Infoblox Error adding TXT record: %d %s', e, e)
            raise errors.PluginError('Error communicating with the Infoblox API: {0}'.format(e))

        logger.debug('Successfully added TXT record with record_id: %s', record_id)

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain (not used).
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

		record_id = self._find_txt_record_id(record_name, record_content)
		if record_id:
			try:
				self.recordtxt('delete', parameters=record_id)
				logger.debug('Successfully deleted TXT record.')
			except e:
				logger.warn('Encountered error deleting TXT record: %s', e)
		else:
			logger.debug('TXT record not found; no cleanup needed.')


    def _find_txt_record_id(self, zone_id, record_name, record_content):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str zone_id: The zone_id which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """

        params = {'name': record_name,
                  'text': record_content}
        try:
            records = self.recordtxt(parameters=params)
        except e:
            logger.debug('Encountered error getting TXT record_id: %s', e)
            records = []

        if len(records) > 0:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.
            return records[0]
        else:
            logger.debug('Unable to find TXT record.')

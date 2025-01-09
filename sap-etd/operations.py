""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions
import requests
import urllib.parse

logger = get_logger('sap-etd')


def check_response(response):
    try:
        if response.ok:
            if 'LEEF' in response.content.decode('utf-8'):
                return response.content.decode('utf-8')
            return response.json()
        else:
            if response.status_code == 500 or response.content == 'invalid%20date':
                return []
            res_text = response.content
            if isinstance(res_text, bytes):
                res_text = urllib.parse.unquote(res_text.decode())
            raise ConnectorError(
                'Fail To request API {0} response is : {1}'.format(str(response.url), res_text))
    except Exception as e:
        raise ConnectorError(e)


def get_config_data(config):
    host = config.get('server', None)
    if not host.startswith('http') or not host.startswith('https'):
        host = 'https://' + host
    user = config.get('user', None)
    password = config.get('password', None)
    port = config.get('port', None)
    verify_ssl = config.get('verify_ssl', True)
    return host.strip('/'), user, password, port, verify_ssl


def make_rest_call(endpoint, config, data=None, params=None, files=None, method='GET'):
    host, user, password, port, verify_ssl = get_config_data(config)
    if port:
        url = "{host}:{port}/{endpoint}".format(host=host, port=port, endpoint=endpoint)
    else:
        url = "{host}/{endpoint}".format(host=host, endpoint=endpoint)
    try:
        r = requests.request(method, url, auth=(user, password), data=data, params=params,
                             verify=verify_ssl)
        response = check_response(r)
        return response
    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)


def build_payload(params):
    payload = dict()    
    for key, value in params.items():
        if value != '':
            payload[key] = value
    logger.info('payload: {}'.format(payload))
    return payload


def get_alert(config, params):
    try:
        api_endpoint = 'sap/secmon/services/Alerts.xsjs'
        query_data = build_payload(params)
        return make_rest_call(api_endpoint, config, params=query_data)
    except Exception as e:
        raise ConnectorError(e)


def _check_health(config):
    try:
        query_param = {'$batchSize': 1}
        response = get_alert(config, params=query_param)
        if response:
            return True
    except Exception as e:
        raise ConnectorError(e)


operations = {
    'get_alert': get_alert
}

# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
import json
from enum import Enum

# Remove for publishing....
import logging
logger = logging.getLogger('cdo_common')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/tmp/cdo_common.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


class CDORegions(Enum):
    """ CDO API Endpoints by Region"""
    us = 'www.defenseorchestrator.com'
    eu = 'www.defenseorchestrator.eu'
    apj = 'apj.cdo.cisco.com'

    @classmethod
    def get_endpoint(region: object, input_region: str) -> str:
        """ Given a region (input_region) , return the endpoint"""
        return region[input_region].value


class CDORequests:
    @staticmethod
    def create_session(token: str, version) -> str:
        """Helper function to set the auth token and accept headers in the API request"""
        http_session = requests.Session()
        http_session.headers = {"Authorization": f"Bearer {token.strip()}", "Accept": "*/*",
                                "Content-Type": "application/json", "User-Agent": f"AnsibleCDOModule/{version}"}
        return http_session

    # TODO: HTTP Error Catching Wrapper
    @staticmethod
    def get(http_session: requests.Session, url: str, path: str = None, query: dict = None) -> str:
        """ Given the CDO endpoint, path, and query, return the json payload from the API """
        uri = url if path is None else f"{url}/{path}"
        result = http_session.get(url=uri, headers=http_session.headers, params=query)
        logger.debug(result.status_code)
        logger.debug(result.text)
        if result.text:
            return result.status_code, result.json()
        else:
            return result.status_code, None

    @staticmethod
    def post(http_session: requests.Session, url: str, path: str = None, data: dict = None, query: dict = None) -> str:
        """ Given the CDO endpoint, path, and query, post the json data and return the json payload from the API """
        uri = url if path is None else f"{url}/{path}"
        result = http_session.post(url=uri, params=query, json=data)
        if result.text:
            return result.status_code, result.json()
        else:
            return result.status_code, None

    @staticmethod
    def put(http_session: requests.Session, url: str, path: str = None, data: dict = None, query: dict = None) -> str:
        """ Given the CDO endpoint, path, and query, return the json payload from the API """
        uri = url if path is None else f"{url}/{path}"
        logger.debug(f"URI: {uri}")
        logger.debug(f"DATA: {data}")
        result = http_session.put(url=uri, headers=http_session.headers, params=query, json=data)
        logger.debug(result.status_code)
        logger.debug(result.text)
        if result.text and result.status_code in range(200,300):
            return result.status_code, result.json()
        else:
            return result.status_code, None

    @staticmethod
    def delete():
        pass
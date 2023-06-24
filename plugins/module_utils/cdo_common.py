# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
from enum import Enum


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
    def create_session(token: str) -> str:
        """Helper function to set the auth token and accept headers in the API request"""
        http_session = requests.Session()
        http_session.headers = {"Authorization": f"Bearer {token.strip()}", "Accept": "application/json",
                                "Content-Type": "application/json;charset=utf-8"}
        return http_session

    # TODO: HTTP Error Catching Wrapper
    @staticmethod
    def get(http_session: requests.Session, url: str, path: str = None, query: dict = None) -> str:
        """ Given the CDO endpoint, path, and query, return the json payload from the API """
        uri = url if path is None else f"{url}/{path}"
        result = http_session.get(url=uri, headers=http_session.headers, params=query)
        if result.text:
            return result.json()

    @staticmethod
    def post():
        pass

    @staticmethod
    def put():
        pass

    @staticmethod
    def delete():
        pass

# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
import json
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
    def req_headers(token: str) -> dict:
        return {"Authorization": f"Bearer {token.strip()}", "Accept": "application/json", "Content-Type": "application/json;charset=utf-8"}

    # TODO: HTTP Error Catching Wrapper
    @staticmethod
    def get(url: str, headers: dict, path: str = None, query: dict = None) -> str:
        """ Given the CDO endpoint, path, and query, return the json payload from the API """
        uri = url if path is None else f"{url}/{path}"
        result = requests.get(
            url=f"https://{uri}", headers=headers, params=query)
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

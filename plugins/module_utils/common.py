# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.cisco.cdo.plugins.module_utils.api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.query import CDOQuery
from ansible_collections.cisco.cdo.plugins.module_utils.requests import CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.errors import DeviceNotFound
import urllib.parse
import requests


def get_lar_list(module_params: dict, http_session: requests.session, endpoint: str):
    """ Return a list of lars (SDC/CDG from CDO) """
    path = CDOAPI.LARS.value
    query = CDOQuery.get_lar_query(module_params)
    if query is not None:
        path = f"{path}?q={urllib.parse.quote_plus(query)}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def inventory_count(http_session: requests.session, endpoint: str, filter: str = None):
    """Given a filter criteria, return the number of devices that match the criteria"""
    return CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?agg=count&q={filter}"
    )['aggregationQueryResult']


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def get_device(http_session: requests.session, endpoint: str, uid: str):
    """ Given a device uid, retreive the specific device model of the device """
    return CDORequests.get(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}")


def get_cdfmc(http_session: requests.session, endpoint: str):
    """ Get the cdFMC object for this tenant if one exists """
    query = CDOQuery.get_cdfmc_query()
    response = CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?q={query['q']}")
    if len(response) == 0:
        raise DeviceNotFound("A cdFMC was not found in this tenant")
    return response[0]


def working_set(http_session: requests.session, endpoint: str, uid: str):
    data = {"selectedModelObjects": [{"modelClassKey": "targets/devices", "uuids": [uid]}],
            "workingSetFilterAttributes": []}
    return CDORequests.post(http_session, f"https://{endpoint}", path=f"{CDOAPI.WORKSET.value}", data=data)


def inventory(module_params: dict, http_session: requests.session, endpoint: str, extra_filter: str = None,
              limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: Support paging
    query = CDOQuery.get_inventory_query(module_params, extra_filter=extra_filter)
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)

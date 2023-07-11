#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: add_ftd

short_description: This module is to add, modify, read, and remove devivces on Cisco Defense Orchestrator (CDO).

version_added: "1.0.0"

description: This module is to add, modify, read, and remove inventory (devices) on Cisco Defense Orchestrator (CDO). 
With this module, one can add, modify, read, and remove the following devices in a CDO tenant's inventory: 
[FTD, ASA, IOS]

options:
    api_key:
        description:
            - API key for the tenant on which we wish to operate
        required: true
        type: str
    region:
        description:
            - The region where the CDO tenant exists 
        choices: [us, eu, apj]
        default: us
        required: true
        type: str
    add_ftd:
        description: This is the message to send to the test module.
        required: false
        type: dict

author:
    - Aaron Hackney (@aaronhackney)
requirements:
  - tbd
  
'''

EXAMPLES = r'''
- name: Add FTD CDO inventory (CLI Method)
  hosts: localhost
  tasks:
    - name: Add FTD to CDO and cdFMC
      cisco.cdo.cdo_add_ftd:
        api_key: "{{ lookup('ansible.builtin.env', 'CDO_API_KEY') }}"
        region: 'us'
        add_ftd:
          onboard_method: 'cli'
          access_control_policy: 'Default Access Control Policy'
          name: 'ElPaso'
          is_virtual: true
          performance_tier: FTDv10
          license:
            - BASE
            - THREAT
            - URLFilter
            - MALWARE
            - PLUS
      register: added_device
      
- name: Add FTD CDO inventory (LTP Method)
  hosts: localhost
  tasks:
    - name: Add FTD to CDO and cdFMC
      cisco.cdo.cdo_add_ftd:
        api_key: "{{ lookup('ansible.builtin.env', 'CDO_API_KEY') }}"
        region: 'us'
        add_ftd:
          onboard_method: 'ltp'
          serial: 'JAD245008W2'
          access_control_policy: 'Default Access Control Policy'
          name: 'ElPaso'
          license:
            - BASE
            - THREAT
            - URLFilter
            - MALWARE
            - PLUS
      register: added_device
'''

# fmt: off 
# Remove for publishing....
import logging
logger = logging.getLogger('inventory_module')
logging.basicConfig()
fh = logging.FileHandler('/tmp/cdo_inventory.log')
fh.setLevel(logging.DEBUG)
logger.setLevel(logging.DEBUG)
logger.addHandler(fh)
# fmt: on

# fmt: off 
from time import sleep
from ansible_collections.cisco.cdo.plugins.module_utils.query import CDOQuery
from ansible_collections.cisco.cdo.plugins.module_utils.api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.requests import CDORegions, CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.devices import FTDModel, FTDMetaData
from ansible_collections.cisco.cdo.plugins.module_utils.args_common import (
    INVENTORY_ARGUMENT_SPEC,
    REQUIRED_ONE_OF,
    MUTUALLY_EXCLUSIVE,
    REQUIRED_IF
)
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.cisco.cdo.plugins.module_utils.errors as cdo_errors
import urllib.parse
import requests
import base64
# fmt: on

__version__ = "1.0.0"


def new_ftd_polling(module_params: dict, http_session: requests.session, endpoint: str, uid: str):
    """ Check that the new FTD specific device has been created before attempting move to the onboarding step """
    for i in range(module_params['retry']):
        try:
            return get_specific_device(http_session, endpoint, uid)
        except cdo_errors.DeviceNotFound:
            sleep(module_params['delay'])
            continue
    raise cdo_errors.AddDeviceFailure(f"Failed to add FTD {module_params['name']}")


def get_cdfmc(http_session: requests.session, endpoint: str):
    """ Get the cdFMC object for this tenant if one exists """
    query = CDOQuery.get_cdfmc_query()
    response = CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?q={query['q']}")
    if len(response) == 0:
        raise cdo_errors.DeviceNotFound("A cdFMC was not found in this tenant")
    return response[0]


def get_cdfmc_access_policy_list(http_session: requests.session, endpoint: str, cdfmc_host: str, domain_uid: str,
                                 limit: int = 50, offset: int = 0, access_list_name=None):
    """ Given the domain uuid of the cdFMC, retreive the list of access policies """
    # TODO: use the FMC collection to retrieve this
    http_session.headers['fmc-hostname'] = cdfmc_host
    path = f"{CDOAPI.FMC_ACCESS_POLICY.value.replace('{domain_uid}', domain_uid)}"
    path = f"{path}?{CDOQuery.get_cdfmc_policy_query(limit, offset, access_list_name)}"
    response = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    if response['paging']['count'] == 0:
        if access_list_name is not None:
            raise cdo_errors.ObjectNotFound(f"Access Policy {access_list_name} not found on cdFMC.")
    return response


def get_device(http_session: requests.session, endpoint: str, uid: str):
    """ Given a device uid, retreive the specific device model of the device """
    return CDORequests.get(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}")


def update_ftd_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    return CDORequests.put(http_session, f"https://{endpoint}", path=f"{CDOAPI.FTDS.value}/{uid}", data=data)


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def inventory_count(http_session: requests.session, endpoint: str, filter: str = None):
    """Given a filter criteria, return the number of devices that match the criteria"""
    return CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?agg=count&q={filter}"
    )['aggregationQueryResult']


def add_ftd_ltp(module_params: dict, http_session: requests.session, endpoint: str, ftd_device: FTDModel, fmc_uid: str):
    """ Onboard an FTD to cdFMC using LTP (serial number onboarding)"""
    # 1. Check to see if the serial number has already been claimed
    if (not inventory_count(http_session, endpoint, filter=f"serial:{module_params['serial']}") and
            not inventory_count(http_session, endpoint, filter=f"name:{module_params['serial']}")):
        base64.b64encode(f'{{"nkey": "{module_params["password"]}"}}'.encode('ascii')).decode('ascii')
        payload = {
            "associatedDeviceUid": fmc_uid,
            "deviceType": "FTDC",
            "ipv4": None,
            "larType": "CDG",
            "metadata": ftd_device.metadata.asdict(),
            "model": False,
            "name": module_params['serial'],
            "serial": module_params['serial'],
            "sseDeviceSerialNumberRegistration": {
                "initialProvisionData":
                    base64.b64encode(f'{{"nkey": "{module_params["password"]}"}}'.encode('ascii')).decode('ascii'),
                "sudiSerialNumber": module_params['serial']
            },
            "sseEnabled": True,
            "state": "NEW",
            "tags": {},
            "type": "devices"
        }
        ftd_device = CDORequests.post(http_session, f"https://{endpoint}",
                                      path=CDOAPI.DEVICES.value, data=payload)
        ftd_specific_device = get_specific_device(http_session, endpoint, ftd_device['uid'])  # required polling?
        ftd_device = get_device(http_session, endpoint, ftd_device['uid'])  # refresh device
        trigger_claim = CDORequests.put(http_session, f"https://{endpoint}",
                                        path=f"{CDOAPI.FTDS.value}/{ftd_specific_device['uid']}",
                                        data={"queueTriggerState": "SSE_CLAIM_DEVICE"}
                                        )  # Trigger device claiming
        return ftd_device

    else:
        raise cdo_errors.DuplicateObject(f"Device with serial number {module_params['serial']} exists in tenant")


def add_ftd(module_params: dict, http_session: requests.session, endpoint: str):
    # Get cdFMC details
    cdfmc = get_cdfmc(http_session, endpoint)
    cdfmc_specific_device = get_specific_device(http_session, endpoint, cdfmc['uid'])
    # TODO: Get these from the fmc collection when it supports cdFMC
    access_policy = get_cdfmc_access_policy_list(
        http_session, endpoint, cdfmc['host'], cdfmc_specific_device['domainUid'],
        access_list_name=module_params['access_control_policy'])

    ftd_device = FTDModel(
        name=module_params['name'],
        associatedDeviceUid=cdfmc['uid'],
        metadata=FTDMetaData(
            accessPolicyName=access_policy['items'][0]['name'],
            accessPolicyUuid=access_policy['items'][0]['id'],
            license_caps=','.join(module_params['license']),
            performanceTier=module_params['performance_tier']
        )
    )
    if module_params['onboard_method'].lower() == "ltp":
        ftd_device = add_ftd_ltp(module_params, http_session, endpoint, ftd_device, cdfmc['uid'])
        return f"Serial number {module_params['serial']} ready for LTP onboarding into CDO"
    else:
        # Create the device
        new_device = CDORequests.post(http_session, f"https://{endpoint}",
                                      path=CDOAPI.DEVICES.value, data=ftd_device.asdict())

        # Wait for it to be created and return the specific device model
        result = new_ftd_polling(module_params, http_session, endpoint, new_device['uid'])

        # Enable FTD onboarding on the cdFMC using the specific device uid
        update_ftd_device(http_session, endpoint, result['uid'], {"queueTriggerState": "INITIATE_FTDC_ONBOARDING"})
        result = CDORequests.get(http_session, f"https://{endpoint}",
                                 path=f"{CDOAPI.DEVICES.value}/{new_device['uid']}")
        return f"{module_params['name']} CLI Command: {result['metadata']['generatedCommand']}"


def main():
    result = dict(
        msg='',
        stdout='',
        stdout_lines=[],
        stderr='',
        stderr_lines=[],
        rc=0,
        failed=False,
        changed=False
    )

    module = AnsibleModule(argument_spec=INVENTORY_ARGUMENT_SPEC, required_one_of=[
                           REQUIRED_ONE_OF], mutually_exclusive=MUTUALLY_EXCLUSIVE, required_if=REQUIRED_IF)

    endpoint = CDORegions.get_endpoint(module.params.get('region'))
    http_session = CDORequests.create_session(module.params.get('api_key'), __version__)

    result['stdout'] = add_ftd(module.params.get('add_ftd'), http_session, endpoint)
    result['changed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()

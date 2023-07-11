#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: delete

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
    inventory:
        description:
            - Return a dictionary of json device objects in the current tenant's inventory
        required: false
        type: dict
    add_ftd:
        description: This is the message to send to the test module.
        required: false
        type: dict
    add_asa:
        description:
            - Control to demo if the result of this module is changed or not.
            - Parameter description can be a list as well.
        required: false
        type: bool

author:
    - Aaron Hackney (@aaronhackney)
requirements:
  - tbd
  
'''

EXAMPLES = r'''
- name: Add FTD CDO inventory
  hosts: localhost
  tasks:
    - name: Add FTD to CDO and cdFMC
      cisco.cdo.cdo_inventory:
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

---
- name: Add ASA to CDO inventory
  hosts: localhost
  tasks:
    - name: Add ASA to CDO
      cisco.cdo.cdo_inventory:
        api_key: "{{ lookup('ansible.builtin.env', 'CDO_API_KEY') }}"
        region: 'us'
        add_asa:
          sdc: 'CDO_cisco_aahackne-SDC-1'
          name: 'Austin'
          ipv4: '172.30.4.101'
          port: 8443
          device_type: 'asa'
          username: 'myuser'
          password: 'abc123'
          ignore_cert: true
      register: added_device

---
- name: Add IOS to CDO inventory
  hosts: localhost
  tasks:
    - name: Add IOS to CDO
      cisco.cdo.cdo_inventory:
        api_key: "{{ lookup('ansible.builtin.env', 'CDO_API_KEY') }}"
        region: 'us'
        add_asa_ios:
          sdc: 'CDO_cisco_aahackne-SDC-1'
          name: 'Austin-CSR-1000v'
          ipv4: '172.30.4.250'
          port: 22
          device_type: 'ios'
          username: 'myuser'
          password: 'abc123'
          ignore_cert: true
      register: added_device    
---
- name: Get device inventory details
  hosts: localhost
  tasks:
    - name: Get the CDO inventory for this tenant
      cisco.cdo.cdo_inventory:
        api_key: "{{ lookup('ansible.builtin.env', 'CDO_API_KEY') }}"
        region: "us"
        inventory:
          device_type: "all"
      register: inventory

    - name: Print All Results for all devices, all fields
      ansible.builtin.debug:
        msg:
          "{{ inventory.stdout }}"
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
from ansible_collections.cisco.cdo.plugins.module_utils.crypto import CDOCrypto
from ansible_collections.cisco.cdo.plugins.module_utils.query import CDOQuery
from ansible_collections.cisco.cdo.plugins.module_utils.api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.requests import CDORegions, CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.devices import FTDModel, FTDMetaData, ASAIOSModel
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


def get_cdfmc(http_session: requests.session, endpoint: str):
    """ Get the cdFMC object for this tenant if one exists """
    query = CDOQuery.get_cdfmc_query()
    response = CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?q={query['q']}")
    if len(response) == 0:
        raise cdo_errors.DeviceNotFound("A cdFMC was not found in this tenant")
    return response[0]


def working_set(http_session: requests.session, endpoint: str, uid: str):
    data = {"selectedModelObjects": [{"modelClassKey": "targets/devices", "uuids": [uid]}],
            "workingSetFilterAttributes": []}
    return CDORequests.post(http_session, f"https://{endpoint}", path=f"{CDOAPI.WORKSET.value}", data=data)


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def inventory(module_params: dict, http_session: requests.session, endpoint: str, extra_filter: str = None,
              limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: Support paging
    query = CDOQuery.get_inventory_query(module_params, extra_filter=extra_filter)
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def find_device_for_deletion(module_params: dict, http_session: requests.session, endpoint: str):
    if module_params['device_type'].upper() == "FTD":
        extra_filter = "AND (deviceType:FTDC)"
    else:
        extra_filter = f"AND (deviceType:{module_params['device_type'].upper()})"
    module_params['filter'] = module_params['name']
    device_list = inventory(module_params, http_session, endpoint, extra_filter=extra_filter)
    if len(device_list) < 1:
        raise cdo_errors.DeviceNotFound(f"Cannot delete {module_params['name']} - device by that name not found")
    elif len(device_list) > 1:
        raise cdo_errors.TooManyMatches(f"Cannot delete {module_params['name']} - more than 1 device matches name")
    else:
        return device_list[0]


def delete_device(module_params: dict, http_session: requests.session, endpoint: str):
    device = find_device_for_deletion(module_params, http_session, endpoint)
    working_set(http_session, endpoint, device['uid'])
    if module_params['device_type'].upper() == "ASA" or module_params['device_type'].upper() == "IOS":
        CDORequests.delete(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{device['uid']}")
    elif module_params['device_type'].upper() == "FTD":
        cdfmc = get_cdfmc(http_session, endpoint)
        cdfmc_specific_device = get_specific_device(http_session, endpoint, cdfmc['uid'])
        data = {
            "queueTriggerState": "PENDING_DELETE_FTDC",
            "stateMachineContext": {"ftdCDeviceIDs": f"{device['uid']}"}
        }
        result = CDORequests.put(http_session, f"https://{endpoint}",
                                 path=f"{CDOAPI.FMC.value}/{cdfmc_specific_device['uid']}", data=data)


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
    result['stdout'] = delete_device(module.params.get('delete'), http_session, endpoint)
    result['changed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()

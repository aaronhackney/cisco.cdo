#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# Apache License v2.0+ (see LICENSE or http://www.apache.org/licenses/)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cdo_inventory

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
    
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - my_namespace.my_collection.my_doc_fragment_name

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
- name: Add ASA CDO inventory
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
import logging
from time import sleep
from ansible_collections.cisco.cdo.plugins.module_utils.crypto import CDOCrypto
from ansible_collections.cisco.cdo.plugins.module_utils.query import CDOQuery
from ansible_collections.cisco.cdo.plugins.module_utils.api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.requests import CDORegions, CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.args_common import (
    INVENTORY_ARGUMENT_SPEC,
    REQUIRED_ONE_OF,
    MUTUALLY_EXCLUSIVE
)
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.cisco.cdo.plugins.module_utils.errors as cdo_errors
import urllib.parse
import requests
# fmt: on

__version__ = "1.0.0"

# Remove for publishing....
logger = logging.getLogger('cdo_inventory')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/tmp/cdo_inventory.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


def connectivity_poll(module_params: dict, http_session: requests.session, endpoint: str, uid: str) -> bool:
    """ Check device connectivity or fail after retry attempts have expired"""
    for i in range(module_params['retry']):
        device = get_device(http_session, endpoint, uid)
        if device['connectivityState'] == -2:
            if module_params['ignore_cert']:
                update_device(http_session, endpoint, uid, data={"ignoreCertificate": True})
                return True
            else:
                # TODO: Delete the device we just attempted to add....
                raise cdo_errors.InvalidCertificate(f"{device['connectivityError']}")
        if device['connectivityState'] > -1 or device['status'] == "WAITING_FOR_DATA":
            return True
        sleep(module_params['delay'])
    raise cdo_errors.DeviceUnreachable(
        f"Device {module_params['name']} was not reachable at "
        f"{module_params['ipv4']}:{module_params['port']} by CDO"
    )


def credentails_polling(module_params: dict, http_session: requests.session, endpoint: str, uid: str) -> bool:
    """ Check credentials have been used successfully  or fail after retry attempts have expired"""
    for i in range(module_params['retry']):
        result = CDORequests.get(
            http_session, f"https://{endpoint}", path=f"{CDOAPI.ASA_CONFIG.value}/{uid}")
        if result['state'] == "BAD_CREDENTIALS":
            raise cdo_errors.CredentialsFailure(
                f"Credentials provided for device {module_params['name']} were rejected.")
        elif result['state'] == "PENDING_GET_CONFIG_DONE" or result['state'] == "DONE":
            return True
        sleep(module_params['delay'])
    raise cdo_errors.APIError(
        f"Credentials for device {module_params['name']} were sent but we never reached a known good state.")


def new_ftd_polling(module_params: dict, http_session: requests.session, endpoint: str, uid: str):
    """ Check that the new FTD specific device has been created before attempting move to the onboarding step """
    for i in range(module_params['retry']):
        try:
            return get_specific_device(http_session, endpoint, uid)
        except cdo_errors.DeviceNotFound:
            sleep(module_params['delay'])
            continue
    raise cdo_errors.AddDeviceFailure(f"Failed to add FTD {module_params['name']}")


def get_lar_list(module_params: dict, http_session: requests.session, endpoint: str):
    """ Return a list of lars (SDC/CDG from CDO) """
    path = CDOAPI.LARS.value
    query = CDOQuery.get_lar_query(module_params)
    if query is not None:
        path = f"{path}?q={urllib.parse.quote_plus(query)}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


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
    http_session.headers['fmc-hostname'] = cdfmc_host  # This header is the magic that hits cdFMC api and not CDO API
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


def update_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    """ Update an eixsting device's attributes """
    return CDORequests.put(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}", data=data)


def update_ftd_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    return CDORequests.put(http_session, f"https://{endpoint}", path=f"{CDOAPI.FTDS.value}/{uid}", data=data)


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def inventory(module_params: dict, http_session: requests.session, endpoint: str, filter: str = None,
              limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: Support paging
    query = CDOQuery.get_inventory_query(module_params)
    logger.debug(f"Filter: {query}")
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def add_ftd(module_params: dict, http_session: requests.session, endpoint: str):
    # Get cdFMC details
    cdfmc = get_cdfmc(http_session, endpoint)
    cdfmc_specific_device = get_specific_device(http_session, endpoint, cdfmc['uid'])
    # Should I be getting these from the fmc collection?
    acess_policy = get_cdfmc_access_policy_list(
        http_session, endpoint, cdfmc['host'], cdfmc_specific_device['domainUid'],
        access_list_name=module_params['access_control_policy'])

    device_data = {
        'name': module_params['name'],
        'associatedDeviceUid': cdfmc['uid'],
        'metadata': {
            'accessPolicyName': acess_policy['items'][0]['name'],
            'accessPolicyUuid': acess_policy['items'][0]['id'],
            'license_caps': ','.join(module_params['license']),
            'performanceTier': module_params['performance_tier']
        },
        'deviceType': 'FTDC',
        'model': "false",
        'state': 'NEW',
        'type': 'devices'
    }
    # Create the device
    new_device = CDORequests.post(http_session, f"https://{endpoint}", path=CDOAPI.DEVICES.value, data=device_data)

    # Wait for it to be created and return the specific device model
    result = new_ftd_polling(module_params, http_session, endpoint, new_device['uid'])

    # Enable FTD onboarding on the cdFMC using the specific device uid
    update_ftd_device(http_session, endpoint, result['uid'], {"queueTriggerState": "INITIATE_FTDC_ONBOARDING"})
    result = CDORequests.get(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{new_device['uid']}")

    # Get onboarding FTD CLI commands
    return f"{module_params['name']} CLI Command: {result['metadata']['generatedCommand']}"


def add_asa(module_params: dict, http_session: requests.session, endpoint: str):
    """ Add ASA or IOS device to CDO"""

    lar_list = get_lar_list(module_params, http_session, endpoint)
    if len(lar_list) != 1:
        raise (cdo_errors.SDCNotFound(f"Could not find SDC"))
    else:
        lar = lar_list[0]

    device_data = {
        'deviceType': module_params['device_type'].upper(),
        'host': module_params['ipv4'],
        'ipv4': f"{module_params['ipv4']}:{module_params['port']}",
        'larType': 'CDG' if lar['cdg'] else 'SDC',
        'larUid': lar['uid'],
        'model': False,
        'name': module_params['name'],
    }

    if module_params['ignore_cert']:
        device_data['ignore_cert'] = True

    path = CDOAPI.DEVICES.value
    device = CDORequests.post(http_session, f"https://{endpoint}", path=path, data=device_data)
    connectivity_poll(module_params, http_session, endpoint, device['uid'])

    # Get UID of specific device, encrypt crednetials, send crendtials to SDC
    specific_device = get_specific_device(http_session, endpoint, device['uid'])

    creds_crypto = CDOCrypto.encrypt_creds(module_params['username'], module_params['password'], lar)
    path = f"{CDOAPI.ASA_CONFIG.value}/{specific_device['uid']}"
    CDORequests.put(http_session, f"https://{endpoint}", path=path, data=creds_crypto)
    credentails_polling(module_params, http_session, endpoint, specific_device['uid'])


def main():

    # Instantiate the module
    module = AnsibleModule(argument_spec=INVENTORY_ARGUMENT_SPEC, required_one_of=[
                           REQUIRED_ONE_OF], mutually_exclusive=MUTUALLY_EXCLUSIVE)

    # The API endpoint we will hit based on region
    endpoint = CDORegions.get_endpoint(module.params.get('region'))

    # Build the return data structure
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

    # Create the HTTP session and headers
    # TODO provide module versioning, not ansible version
    http_session = CDORequests.create_session(module.params.get('api_key'), __version__)

    # Execute the function based on the action and pass the input parameters
    if module.params.get('inventory') is not None:
        result['stdout'] = inventory(module.params.get('inventory'),  http_session, endpoint)
        logger.debug(f"Inventory: {inventory(module.params.get('inventory'),  http_session, endpoint)}")
        result['changed'] = False
    elif module.params.get('add_asa') is not None:
        # api_result = add_device(module, http_session, endpoint
        result['stdout'] = add_asa(module.params.get('add_asa'),  http_session, endpoint)
        result['changed'] = True
    elif module.params.get('add_ftd') is not None:
        result['stdout'] = add_ftd(module.params.get('add_ftd'), http_session, endpoint)
        result['changed'] = True

    # Return the module results to the calling playbook
    module.exit_json(**result)


if __name__ == '__main__':
    main()

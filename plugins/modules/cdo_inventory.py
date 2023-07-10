#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

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
fh = logging.FileHandler('cdo_inventory_2.log')
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
    MUTUALLY_EXCLUSIVE
)
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.cisco.cdo.plugins.module_utils.errors as cdo_errors
import urllib.parse
import requests
# fmt: on

__version__ = "1.0.0"


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


def asa_credentails_polling(module_params: dict, http_session: requests.session, endpoint: str, uid: str) -> bool:
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


def ios_credentials_polling(module_params: dict, http_session: requests.session, endpoint: str, uid: str) -> True:
    for i in range(module_params['retry']):
        device = get_device(http_session, endpoint, uid)
        if device['connectivityState'] == -5:
            sleep(module_params['delay'])
        elif device['connectivityError'] is not None:
            raise cdo_errors.CredentialsFailure(device['connectivityError'])
        elif device['connectivityState'] > 0:
            return True
    raise cdo_errors.CredentialsFailure(f"Device remains in connectivity state {device['connectivityState']}")


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


def update_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    """ Update an eixsting device's attributes """
    return CDORequests.put(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}", data=data)


def update_ftd_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    return CDORequests.put(http_session, f"https://{endpoint}", path=f"{CDOAPI.FTDS.value}/{uid}", data=data)


def working_set(http_session: requests.session, endpoint: str, uid: str):
    data = {"selectedModelObjects": [{"modelClassKey": "targets/devices", "uuids": [uid]}],
            "workingSetFilterAttributes": []}
    return CDORequests.post(http_session, f"https://{endpoint}", path=f"{CDOAPI.WORKSET.value}", data=data)


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def inventory_count(http_session: requests.session, endpoint: str, filter: str = None):
    """Given a filter criteria, return the number of devices that match the criteria"""
    logger.debug(CDORequests.get(http_session, f"https://{endpoint}", path="f{CDOAPI.DEVICES}?agg=count&q={filter}"))
    return CDORequests.get(http_session, f"https://{endpoint}", path="f{CDOAPI.DEVICES}?agg=count&q={filter}")


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


def add_ftd_ltp(module_params: dict, http_session: requests.session, endpoint: str, ftd_device: FTDModel):
    """ Onboard an FTD to cdFMC using LTP (serial number onboarding)"""
    # serial:JAD245008W2
    count = inventory_count(http_session, endpoint, filter=f"serial:{module_params['serial']}")
    logger.debug(f"Count by serial: {count}")
    count = inventory_count(http_session, endpoint, filter=f"name:{module_params['serial']}")
    logger.debug(f"Count by name: {count}")


def add_ftd(module_params: dict, http_session: requests.session, endpoint: str):
    logger.debug(f"Onboard method: {module_params['onboard_method'].lower()}")

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
    logger.debug(f"Onboard method: {module_params['onboard_method'].lower()}")
    if module_params['onboard_method'].lower() == "ltp":
        add_ftd_ltp(module_params, http_session, endpoint, ftd_device)
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

    # Get onboarding FTD CLI commands
    return f"{module_params['name']} CLI Command: {result['metadata']['generatedCommand']}"


def add_asa_ios(module_params: dict, http_session: requests.session, endpoint: str):
    """ Add ASA or IOS device to CDO"""

    lar_list = get_lar_list(module_params, http_session, endpoint)
    if len(lar_list) != 1:
        raise (cdo_errors.SDCNotFound(f"Could not find SDC"))
    else:
        lar = lar_list[0]

    asa_ios_device = ASAIOSModel(deviceType=module_params['device_type'].upper(),
                                 host=module_params['ipv4'],
                                 ipv4=f"{module_params['ipv4']}:{module_params['port']}",
                                 larType='CDG' if lar['cdg'] else 'SDC',
                                 larUid=lar['uid'],
                                 model=False,
                                 name=module_params['name']
                                 )

    if module_params['ignore_cert']:
        asa_ios_device.ignore_cert = False

    path = CDOAPI.DEVICES.value
    device = CDORequests.post(http_session, f"https://{endpoint}", path=path, data=asa_ios_device.asdict())
    connectivity_poll(module_params, http_session, endpoint, device['uid'])

    creds_crypto = CDOCrypto.encrypt_creds(module_params['username'], module_params['password'], lar)

    # Get UID of specific device, encrypt crednetials, send crendtials to SDC
    if module_params['device_type'].upper() == "ASA":
        creds_crypto['state'] = "CERT_VALIDATED"
        specific_device = get_specific_device(http_session, endpoint, device['uid'])
        path = f"{CDOAPI.ASA_CONFIG.value}/{specific_device['uid']}"
        CDORequests.put(http_session, f"https://{endpoint}", path=path, data=creds_crypto)
        asa_credentails_polling(module_params, http_session, endpoint, specific_device['uid'])
    elif module_params['device_type'].upper() == "IOS":
        creds_crypto['stateMachineContext'] = {"acceptCert": True}
        path = f"{CDOAPI.DEVICES.value}/{device['uid']}"
        CDORequests.put(http_session, f"https://{endpoint}", path=path, data=creds_crypto)
        ios_credentials_polling(module_params, http_session, endpoint, device['uid'])


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
                           REQUIRED_ONE_OF], mutually_exclusive=MUTUALLY_EXCLUSIVE)

    endpoint = CDORegions.get_endpoint(module.params.get('region'))
    http_session = CDORequests.create_session(module.params.get('api_key'), __version__)

    if module.params.get('inventory') is not None:
        result['stdout'] = inventory(module.params.get('inventory'),  http_session, endpoint)
        result['changed'] = False
    elif module.params.get('add_asa_ios') is not None:
        result['stdout'] = add_asa_ios(module.params.get('add_asa_ios'),  http_session, endpoint)
        result['changed'] = True
    elif module.params.get('add_ftd') is not None:
        result['stdout'] = add_ftd(module.params.get('add_ftd'), http_session, endpoint)
        result['changed'] = True
    elif module.params.get('delete') is not None:
        result['stdout'] = delete_device(module.params.get('delete'), http_session, endpoint)
        result['changed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    logger.warning("Getting started....")
    main()

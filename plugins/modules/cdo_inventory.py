#!/usr/bin/python
import requests
import urllib.parse
import ansible_collections.cisco.cdo.plugins.module_utils.cdo_errors as cdo_errors
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_requests import CDORegions, CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_query import CDOQuery
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_crypto import CDOCrypto

# Remove for publishing....
import logging
logger = logging.getLogger('cdo_inventory')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/tmp/cdo_inventory.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)

version = "1.0.0"


def connectivity_poll(module: AnsibleModule, http_session: requests.session, endpoint: str, uid: str) -> bool:
    """ Get the device until connectivit has been established or fail after retry attempts have expired"""

    for i in range(module.params.get('retry')):
        status_code, device = get_device(http_session, endpoint, uid)
        if device['connectivityState'] == -2:
            if module.params.get('ignore_cert'):
                status_code, result = update_device(http_session, endpoint, uid, data={"ignoreCertificate": True})
                return True
            else:
                # TODO: Delete the device we just attempted to add....
                raise cdo_errors.InvalidCertificate(f"{device['connectivityError']}")
        if device['connectivityState'] > -1 or device['status'] == "WAITING_FOR_DATA":
            return True
        sleep(module.params.get('delay'))
    raise cdo_errors.DeviceUnreachable(
        f"Device {module.params.get('name')} was not reachable at "
        f"{module.params.get('ipv4')}:{module.params.get('port')} by CDO"
    )


def credentails_polling(module: AnsibleModule, http_session: requests.session, endpoint: str, uid: str) -> bool:
    for i in range(module.params.get('retry')):
        status_code, result = CDORequests.get(
            http_session, f"https://{endpoint}", path=f"{CDOAPI.ASA_CONFIG.value}/{uid}")
        if result['state'] == "BAD_CREDENTIALS":
            raise cdo_errors.CredentialsFailure(
                f"Credentials provided for device {module.params.get('name')} were rejected.")
        elif result['state'] == "PENDING_GET_CONFIG_DONE" or result['state'] == "DONE":
            return True
        sleep(module.params.get('delay'))
    raise cdo_errors.APIError(
        f"Credentials for device {module.params.get('name')} were sent but we never reached a known good state.")


def new_ftd_polling(module: AnsibleModule, http_session: requests.session, endpoint: str, uid: str):
    for i in range(module.params.get('retry')):
        logger.debug("Running ftd poller")
        try:
            status_code, result = get_specific_device(http_session, endpoint, uid)
            if status_code == 200:
                return status_code, result
        except cdo_errors.DeviceNotFound:
            sleep(module.params.get('delay'))
            logger.debug(f"Device not found")
            continue
    raise cdo_errors.AddDeviceFailure(f"Failed to add FTD {module.params.get('name')}")


def get_lar_list(module: AnsibleModule, http_session: requests.session, endpoint: str):
    """ Return a list of lars (SDC/CDG from CDO) """
    path = CDOAPI.LARS.value
    query = CDOQuery.get_lar_query(module)
    if query is not None:
        path = f"{path}?q={urllib.parse.quote_plus(query)}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def get_cdfmc(http_session: requests.session, endpoint: str):
    query = CDOQuery.get_cdfmc_query()
    status_code, response = CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}?q={query['q']}")
    if len(response) == 0:
        raise cdo_errors.DeviceNotFound("A cdFMC was not found in this tenant")
    return status_code, response[0]


def get_cdfmc_access_policy_list(http_session: requests.session, endpoint: str, cdfmc_host: str, domain_uid: str,
                                 limit: int = 50, offset: int = 0, access_list_name=None):
    http_session.headers['fmc-hostname'] = cdfmc_host
    path = f"{CDOAPI.FMC_ACCESS_POLICY.value.replace('{domain_uid}', domain_uid)}"
    path = f"{path}?{CDOQuery.get_cdfmc_policy_query(limit, offset, access_list_name)}"
    status_code, response = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    if response['paging']['count'] == 0:
        if access_list_name is not None:
            raise cdo_errors.ObjectNotFound(f"Access Policy {access_list_name} not found on cdFMC.")
    return status_code, response


def get_device(http_session: requests.session, endpoint: str, uid: str):
    """ Given a device uid, retreive the device specific details """
    status_code, result = CDORequests.get(http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}")
    return status_code, result


def update_device(http_session: requests.session, endpoint: str, uid: str, data: dict):
    status_code, result = CDORequests.put(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{uid}", data=data)
    return status_code, result


def get_specific_device(http_session: requests.session, endpoint: str, uid: str) -> str:
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid)
    status_code, result = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    return status_code, result


def get_inventory_summary(module: AnsibleModule, http_session: requests.session, endpoint: str, filter: str = None,
                          limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: Support paging
    query = CDOQuery.get_inventory_query(module)
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    status_code, response_json = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    return response_json


def add_ftd(module: AnsibleModule, http_session: requests.session, endpoint: str):
    # Get cdFMC details
    status_code, cdfmc = get_cdfmc(http_session, endpoint)
    status_code, cdfmc_specific_device = get_specific_device(http_session, endpoint, cdfmc['uid'])
    # Should I be getting these from the fmc collection?
    status_code, acess_policy = get_cdfmc_access_policy_list(
        http_session, endpoint, cdfmc['host'], cdfmc_specific_device['domainUid'],
        access_list_name=module.params.get('access_control_policy'))

    device_data = {
        'name': module.params.get('name'),
        'associatedDeviceUid': cdfmc['uid'],
        'metadata': {
            'accessPolicyName': acess_policy['items'][0]['name'],
            'accessPolicyUuid': acess_policy['items'][0]['id'],
            'license_caps': ','.join(module.params.get('license')),
            'performanceTier': module.params.get('performance_tier')
        },
        'deviceType': 'FTDC',
        'model': "false",
        'state': 'NEW',
        'type': 'devices'
    }
    logger.debug(f"payload: {device_data}")
    # Create the device
    status_code, new_device = CDORequests.post(
        http_session, f"https://{endpoint}", path=CDOAPI.DEVICES.value, data=device_data)

    # Wait for it to be created and return the specific device model
    status_code, result = new_ftd_polling(module, http_session, endpoint, new_device['uid'])

    # Enable FTD onboarding on the cdFMC using the specific device uid
    status_code, result = CDORequests.put(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.FTDS.value}/{result['uid']}",
        data={"queueTriggerState": "INITIATE_FTDC_ONBOARDING"})

    status_code, result = CDORequests.get(
        http_session, f"https://{endpoint}", path=f"{CDOAPI.DEVICES.value}/{new_device['uid']}")
    # Get onboarding FTD CLI commands
    logger.debug(f"CLI Command: {result['metadata']['generatedCommand']}")


def add_asa(module: AnsibleModule, http_session: requests.session, endpoint: str):
    """ Add ASA or IOS device to CDO"""

    status_code, lar_list = get_lar_list(module, http_session, endpoint)
    if len(lar_list) != 1:
        raise (cdo_errors.SDCNotFound(f"Could not find SDC"))
    else:
        lar = lar_list[0]

    device_data = {
        'deviceType': module.params.get('device_type').upper(),
        'host': module.params.get('ipv4'),
        'ipv4': f"{module.params.get('ipv4')}:{module.params.get('port')}",
        'larType': 'CDG' if lar['cdg'] else 'SDC',
        'larUid': lar['uid'],
        'model': False,
        'name': module.params.get('name'),
    }
    if module.params.get('ignore_cert'):
        device_data['ignore_cert'] = True

    path = CDOAPI.DEVICES.value
    status_code, device = CDORequests.post(http_session, f"https://{endpoint}", path=path, data=device_data)
    connectivity_poll(module, http_session, endpoint, device['uid'])

    # Get UID of specific device, encrypt crednetials, send crendtials to SDC
    status_code, specific_device = get_specific_device(http_session, endpoint, device['uid'])
    creds_crypto = CDOCrypto.encrypt_creds(module.params.get('username'), module.params.get('password'), lar)
    path = f"{CDOAPI.ASA_CONFIG.value}/{specific_device['uid']}"
    CDORequests.put(http_session, f"https://{endpoint}", path=path, data=creds_crypto)
    credentails_polling(module, http_session, endpoint, specific_device['uid'])


def remove_inventory(data, http_session):
    result = ""
    return result


def add_device(module: AnsibleModule, http_session: requests.session, endpoint: str):
    if module.params.get('device_type').upper() == "ASA" or module.params.get('device_type').upper() == "IOS":
        add_asa(module, http_session, endpoint)
    if module.params.get('device_type').upper() == "FTD":
        add_ftd(module, http_session, endpoint)


def main():
    # Input variables from playbooks
    fields = {
        "api_key": {"required": True, "type": "str", "no_log": True},
        "region": {
            "default": "us",
            "choices": ['us', 'eu', 'apj'],
            "type": 'str'
        },
        "device_type": {
            "default": "all",
            "choices": ['asa', 'ftd', 'ios', 'meraki', 'all'],
            "type": 'str'
        },
        "action": {
            "default": "list",
            "choices": ['specific_device', 'list', 'add', 'remove'],
            "type": 'str'
        },
        "filter": {
            "default": "",
            "type": 'str'
        },
        "name": {
            "default": "",
            "type": 'str'
        },
        "ipv4": {
            "default": "",
            "type": 'str'
        },
        "port": {
            "default": 443,
            "type": 'int'
        },
        "sdc": {
            "default": "",
            "type": 'str'
        },
        "retry": {
            "default": 10,
            "type": 'int'
        },
        "delay": {
            "default": 1,
            "type": 'int'
        },
        "username": {
            "default": "",
            "type": 'str'
        },
        "password": {
            "default": "",
            "type": 'str'
        },
        "ignore_cert": {
            "default": False,
            "type": 'bool'
        },
        "onboard_method": {
            "default": "cli",
            "choices": ['cli', 'ltp'],
            "type": 'str'
        },
        "access_control_policy": {
            "default": "Default Access Control Policy",
            "type": 'str'
        },
        "license": {
            "type": 'list',
            "choices": ['BASE', 'THREAT', 'URLFilter', 'MALWARE', 'CARRIER', 'PLUS', 'APEX', 'VPNOnly']
        },
        "is_virtual": {
            "default": False,
            "type": 'bool'
        },
        "performance_tier": {
            "choices": ['FTDv', 'FTDv5', 'FTDv10', 'FTDv20', 'FTDv30', 'FTDv50', 'FTDv100'],
            "type": 'str'
        },
    }

    # based on the playbook "action" parameter
    action_map = {
        "specific_device": get_specific_device,
        "list": get_inventory_summary,
        "add": add_device,
        "remove": remove_inventory
    }

    # Instantiate the module
    module = AnsibleModule(argument_spec=fields)

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

    # Create the common HTTP Headers
    http_session = CDORequests.create_session(module.params.get('api_key'), version)

    # Execute the function based on the action and pass the input parameters
    api_result = action_map.get(module.params.get('action'))(module, http_session, endpoint)

    # Return the module results to the calling playbook
    result['stdout'] = api_result
    module.exit_json(**result)


if __name__ == '__main__':
    main()

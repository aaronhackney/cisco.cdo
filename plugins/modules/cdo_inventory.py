#!/usr/bin/python
import requests
import urllib.parse
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


def connectivity_poll(http_session: requests.session, endpoint: str, uid: str, retry: int = 5, delay: int = 1) -> bool | None:
    # Poll until 200 ok or until retries have exceeded
    logger.debug(f"UID: {uid}")
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', uid, 1)
    logger.debug(f"path: {path}")
    for i in range(retry):
        logger.debug(f"{CDOAPI.SPECIFIC_DEVICE.value}/{uid}/specific-device")
        status_code, result = CDORequests.get(
            http_session, endpoint, path=path)
        logger.debug(f"Status Code: {status_code} Itteration {i}")
        if status_code in range(200, 300):
            logger.debug(f"Specific UID: {result['uid']}")
            return result["uid"]
        logger.debug(f"Return text: {result}")
        sleep(delay)


def get_lar_list(module: AnsibleModule, http_session: requests.session, endpoint: str):
    """ Return a list of lars (SDC/CDG from CDO) """
    path = CDOAPI.LARS.value
    query = CDOQuery.get_lar_query(module)
    if query is not None:
        path = f"{path}?q={urllib.parse.quote_plus(query)}"
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def get_specific_device(module: AnsibleModule, http_session: requests.session, endpoint: str) -> str:
    # TODO: Should we get uid as fcn parameter or always as params.get ?
    """ Given a device uid, retreive the device specific details """
    path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', module.params.get('uid'), 1)
    return CDORequests.get(http_session, f"https://{endpoint}", path=path)


def get_inventory_summary(module: AnsibleModule, http_session: requests.session, endpoint: str, filter: str = None,
                          limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: Support paging
    query = CDOQuery.get_inventory_query(module)
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    status_code, response_json = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    logger.debug(f"Status Code {status_code}")
    logger.debug(f"response_json {response_json}")
    return response_json


def add_asa(module: AnsibleModule, http_session: requests.session, endpoint: str):
    """ Add device to CDO"""
    # TODO: This builds ASA, need to modify for FTD...
    # TODO: Add certificate check bypass option...
    status_code, lar_list = get_lar_list(module, http_session, endpoint)
    if len(lar_list) != 1:
        # TODO: Fail with custom message
        return
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
    path = CDOAPI.DEVICES.value

    # TODO: Capture duplicate device and create custom error message
    status_code, device = CDORequests.post(http_session, f"https://{endpoint}", path=path, data=device_data)

    if status_code not in range(200, 300):
        # TODO: Fail with custom error message
        return

    # need to poll device for connectivity
    # Then get specific device uid
    # then add credentials....

    specific_uid = connectivity_poll(
        http_session, f"https://{endpoint}", device['uid'], retry=module.params.get('retry'), delay=module.params.get('delay'))

    if not specific_uid:   # TODO: Fail with custom error message
        logger.debug("Connectivity failed...")
        return

    # 4. Get specific UID of new device
    # # TODO get proper data structure of returned device
    # path = CDOAPI.SPECIFIC_DEVICE.value.replace('{uid}', device["uid"], 1)
    # status_code, specific_device = CDORequests.get(http_session, f"https://{endpoint}", path=path)

    # 5. Encrypt the ASA/IOS credentials (move to own function
    creds_crypto = CDOCrypto.encrypt_creds(module.params.get(
        'username'), module.params.get('password'), lar['larPublicKey']['encodedKey'])
    logger.debug(f"Crypto Creds: {creds_crypto}")
    # 6. send credentials to LAR
    path = f"{CDOAPI.ASA_CONFIG.value}/{specific_uid}"
    logger.debug(f"PATH: {path}")
    status_code, result = CDORequests.put(http_session, f"https://{endpoint}", path=path, data=creds_crypto)

    if not status_code in range(200, 300):
        # TODO: Fail with custom error message
        logger.debug(f"Failed: {result}")
        return
    logger.debug(f"result: {result}")
    # Check connectivity state
    # TODO: retry/wait
    # specific_device = CDORequests.get(http_session, f"https://{endpoint}", path=path)
    # logger.debug(f"Final add output: {specific_device}")


def remove_inventory(data, http_session):
    result = ""
    return result


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
        "uid": {
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
            "default": None,
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
        }
    }

    # based on the playbook "action" parameter
    action_map = {
        "specific_device": get_specific_device,
        "list": get_inventory_summary,
        "add": add_asa,
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
    logger.debug(f"Final output: {api_result}")
    # Return the module results to the calling playbook
    result['stdout'] = api_result
    module.exit_json(**result)


if __name__ == '__main__':
    main()

#!/usr/bin/python
import requests
import urllib.parse
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_common import CDORegions, CDORequests
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_api_endpoints import CDOAPI
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_query import CDOQuery

import logging

# Remove for publishing....
logger = logging.getLogger('cdo_inventory')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/tmp/cdo_inventory.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


def cdo_get_inventory(module: AnsibleModule, http_session: requests.session, filter: str = None,
                      limit: int = 50, offset: int = 0) -> str:
    """ Get CDO inventory """
    # TODO: get return specific device info instead of device info
    # TODO: filter on device name
    # TODO: Support paging
    endpoint = CDORegions.get_endpoint(module.params.get('region'))
    query = CDOQuery.get_inventory_query(device_type=module.params.get('device_type'))
    q = urllib.parse.quote_plus(query['q'])
    r = urllib.parse.quote_plus(query['r'])
    path = f"{CDOAPI.DEVICES.value}?limit={limit}&offset={offset}&q={q}&resolve={r}"
    return CDORequests.get(http_session, url=f"https://{endpoint}", path=path)


def cdo_add_inventory(data, http_session):
    result = ""
    return result


def cdo_remove_inventory(data, http_session):
    result = ""
    return result


def main():
    fields = {
        "api_key": {"required": True, "type": "str", "no_log": True},
        "region": {
            "default": "us",
            "choices": ['us', 'eu', 'apj'],
            "type": 'str'
        },
        "device_type": {
            "default": "all",  # Get all devices in inventory
            "choices": ['asa', 'ftd', 'ios', 'meraki', 'all'],
            "type": 'str'
        },
        "action": {
            "default": "list",  # default scalar value
            "choices": ['list', 'add', 'remove'],  # valid input parameters
            "type": 'str'  # type
        },
    }

    # based on the value of the "state" parameter, run the given function
    action = {
        "list": cdo_get_inventory,
        "add": cdo_add_inventory,
        "remove": cdo_remove_inventory
    }

    # Instantiate the module actions
    module = AnsibleModule(argument_spec=fields)

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
    http_session = CDORequests.create_session(module.params.get('api_key'))

    # Execute the function based on the action and pass the input parameters
    api_result = action.get(module.params.get('action'))(module, http_session)

    result['stdout'] = api_result
    module.exit_json(**result)


if __name__ == '__main__':
    # TODO: Input parameter for device search
    main()

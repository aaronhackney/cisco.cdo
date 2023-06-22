#!/usr/bin/python

import requests
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.cdo.plugins.module_utils.cdo_common import CDORegions, CDORequests


def create_session(token) -> str:
    """Helper function to set the auth token and accept headers in the API request"""
    http_session = requests.Session()
    http_session.headers["Authorization"] = f"Bearer {token.strip()}"
    http_session.headers["Accept"] = "application/json"
    http_session.headers["Content-Type"] = "application/json;charset=utf-8"
    return http_session


def cdo_get_inventory(data, http_session):
    # TODO: Add error handling
    # This string only returns ASAs

    # All devices....
    path = "aegis/rest/v1/services/targets/devices?limit=50&offset=0&q=%28model%3Afalse%29+AND+%28NOT+deviceType%3AFMCE%29&resolve=%5Btargets%2Fdevices.%7Bname%2CcustomLinks%2ChealthStatus%2CsseDeviceRegistrationToken%2CsseDeviceSerialNumberRegistration%2CsseEnabled%2CsseDeviceData%2Cstate%2CignoreCertificate%2CdeviceType%2CconfigState%2CconfigProcessingState%2Cmodel%2Cipv4%2CmodelNumber%2Cserial%2CchassisSerial%2ChasFirepower%2CconnectivityState%2CconnectivityError%2Ccertificate%2CmostRecentCertificate%2Ctags%2CtagKeys%2Ctype%2CassociatedDeviceUid%2CoobDetectionState%2CenableOobDetection%2CdeviceActivity%2CsoftwareVersion%2ClastErrorMap%2CstateMachineDetails%2Cdisks%2CautoAcceptOobEnabled%2CoobCheckInterval%2ClarUid%2ClarType%2Cmetadata%2CfmcApplianceIpv4%2ClastDeployTimestamp%7D%2Cfirepower%2Fftds.%7Bstatus%2ChealthStatus%2Cstate%2CstateMachineDetails%2CftdHaMetadata%2CsupportedFeatures%2CprimaryFtdHaStatus%2CsecondaryFtdHaStatus%2CftdHaError%2CprimaryDeviceDetails%2CsecondaryDeviceDetails%2CisHaCombinedDevice%2CsecurityDbsSyncSchedule%2CautomaticSecurityDbUpdatesEnabled%2CsmartLicense%2CisClusterCombinedDevice%2CclusterControlNodeDeviceDetails%2CclusterDataNodesDeviceDetails%7D%2Cfmc%2Fappliance.%7Bstatus%2Cstate%2CstateMachineDetails%7D%2Cfmc%2Ffmc-managed-device.%7BdeviceModel%2CdeviceSubType%2CfmcApplianceName%2CfmcApplianceIpv4%2ChealthStatus%2Csw_version%2CanalyticsOnly%7D%2Cwsa%2Fwsas.%7Bstatus%2Cstate%2CstateMachineDetails%7D%2Cmeraki%2Fmxs.%7Bstatus%2Cstate%2CstateMachineDetails%2CphysicalDevices%2CboundDevices%2Cnetwork%7D%5D&sort=name%3Aasc"
    result = http_session.get(
        url=f"https://{CDORegions.get_endpoint('us')}/{path}", headers=http_session.headers)
    if result.text:
        return result.json()


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

    # Create the common HTTP Headers
    http_session = create_session(module.params['api_key'])

    # Execute the function based on the action and pass the input parameters
    api_result = action.get(
        module.params['action'])(module.params, http_session)

    # Return the results
    module.exit_json(**api_result)


if __name__ == '__main__':
    # TODO: Input parameter for device search
    main()

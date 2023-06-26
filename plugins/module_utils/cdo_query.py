from ansible.module_utils.basic import AnsibleModule


class CDOQuery:
    """ Helpers for building complex inventory queries"""
    @staticmethod
    def get_inventory_query(module: AnsibleModule = None) -> dict:
        """ Build the inventory query based on what the user is looking for"""
        device_type = module.params.get('device_type')
        filter = module.params.get('filter')
        r = ("[targets/devices.{name,customLinks,healthStatus,sseDeviceRegistrationToken,"
             "sseDeviceSerialNumberRegistration,sseEnabled,sseDeviceData,state,ignoreCertificate,deviceType,"
             "configState,configProcessingState,model,ipv4,modelNumber,serial,chassisSerial,hasFirepower,"
             "connectivityState,connectivityError,certificate,mostRecentCertificate,tags,tagKeys,type,"
             "associatedDeviceUid,oobDetectionState,enableOobDetection,deviceActivity,softwareVersion,"
             "autoAcceptOobEnabled,oobCheckInterval,larUid,larType,metadata,fmcApplianceIpv4,lastDeployTimestamp}]")

        # Build q query
        if filter is not None:
            q = (
                f"((model:false) AND ((name:*{filter}*) OR (ipv4:*{filter}*) OR (serial:*{filter}*) OR "
                f"(interfaces:*{filter}*))) AND (NOT deviceType:FMCE)")
        elif device_type is None or device_type == "all":
            q = "(model:false) AND (NOT deviceType:FMCE)"
        elif device_type == 'asa' or device_type == 'ios':
            q = f"((model:false) AND (deviceType:{device_type.upper()})) AND (NOT deviceType:FMCE)"
        elif device_type == 'ftd':
            q = ("((model:false) AND ((deviceType:FTD) OR (deviceType:FMC_MANAGED_DEVICE) OR (deviceType:FTDC))) AND "
                 "(NOT deviceType:FMCE)")

        # TODO: add meraki and other types...
        # Build r query
        # if device_type == None or device_type == "meraki" or device_type == "all":
        #    r = r[0:-1] + ",meraki/mxs.{status,state,physicalDevices,boundDevices,network}" + r[-1:]

        return {"q": q, "r": r}

from enum import Enum


class CDOAPI(Enum):
    DEVICES = "aegis/rest/v1/services/targets/devices"
    SPECIFIC_DEVICE = "aegis/rest/v1/device/{uid}/specific-device"
    LARS = "aegis/rest/v1/services/targets/proxies"
    ASA_CONFIG = "aegis/rest/v1/services/asa/configs"
    IOS_CONFIG = ""
    FMC_ACCESS_POLICY = "fmc/api/fmc_config/v1/domain/{domain_uid}/policy/accesspolicies"
    FTDS = "aegis/rest/v1/services/firepower/ftds"

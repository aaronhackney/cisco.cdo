from enum import Enum


class CDOAPI(Enum):
    DEVICES = "aegis/rest/v1/services/targets/devices"
    SPECIFIC_DEVICE = "aegis/rest/v1/device/{uid}/specific-device"
    LARS = "aegis/rest/v1/services/targets/proxies"
    ADD_DEVICE = "aegis/rest/v1/services/targets/devices"
    ASA_CONFIG = "aegis/rest/v1/services/asa/configs"

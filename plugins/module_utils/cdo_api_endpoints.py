from enum import Enum


class CDOAPI(Enum):
    DEVICES = "aegis/rest/v1/services/targets/devices"
    SPECIFIC_DEVICE = "aegis/rest/v1/device/{uid}/specific-device"

INVENTORY_ARGUMENT_SPEC = {
    "inventory": {"type": "dict",
                  "options": {
                          "filter": {"type": "str"},
                          "device_type": {"default": "all", "choices": ["all", "asa", "ios", "ftd", "fmc"]}
                  }},
    "add_asa": {"type": "dict",
                "options": {
                        "name": {"default": "", "type": "str"},
                        "ipv4": {"default": "", "type": "str"},
                        "port": {"default": 443, "type": "int"},
                        "sdc": {"default": "", "type": "str"},
                        "username": {"default": "", "type": "str"},
                        "password": {"default": "", "type": "str"},
                        "ignore_cert": {"default": False, "type": "bool"},
                        "device_type": {"default": "asa", "choices": ["asa"], "type": "str"},
                        "retry": {"default": 10, "type": "int"},
                        "delay": {"default": 1, "type": "int"},
                }},
    "add_ftd": {"type": "dict",
                "options": {
                        "name": {"required": True, "type": "str"},
                        "is_virtual": {"default": False, "type": "bool"},
                        "onboard_method": {"default": "cli", "choices": ["cli", "ltp"], "type": "str"},
                        "access_control_policy": {"default": "Default Access Control Policy", "type": "str"},
                        "license": {
                            "type": "list",
                            "choices": ["BASE", "THREAT", "URLFilter", "MALWARE", "CARRIER", "PLUS", "APEX", "VPNOnly"]
                        },
                    "performance_tier": {
                            "choices": ["FTDv", "FTDv5", "FTDv10", "FTDv20", "FTDv30", "FTDv50", "FTDv100"],
                            "type": "str"
                    },
                    "retry": {"default": 10, "type": "int"},
                    "delay": {"default": 1, "type": "int"},
                }},
    "api_key": {"required": True, "type": "str", "no_log": True},
    "region": {"default": "us", "choices": ["us", "eu", "apj"], "type": "str"},
}
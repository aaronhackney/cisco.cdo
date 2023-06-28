from unittest import mock
import ansible_collections.cisco.cdo.plugins.modules.cdo_inventory as cdo_inventory


@mock.patch('cdo_inventory.get_inventory_summary')  # Test actual fcn
@mock.patch('cdo_inventory.AnsibleModule')  # test main() inputs
def test_module_args(mock_module,
                     mock_get_inventory_summary):
    cdo_inventory.main()
    mock_module.assert_called_with(
        argument_spec={
            'api_key': {'required': True, 'type': 'str'},
            'device_type':  {'required': False, 'type': 'str'},
            'action': {'required': False, 'type': 'str'}
        })

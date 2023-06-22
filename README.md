# Ansible Collection - cisco.cdo

# CISCO CDO Ansible Collection

The Ansible Cisco CDO collection includes a variety of Ansible content to help automate the interaction with the Cisco Defense Orcestrator (CDO) platform and the devices managed by the CDO platform.

## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.9.10**.  

For collections that support Ansible 2.9, please ensure you update your network_os to use the fully qualified collection name (for example, cisco.ios.ios). Plugins and modules within a collection may be tested with only specific Ansible versions. A collection may contain metadata that identifies these versions. PEP440 is the schema used to describe the versions of Ansible.

## External requirements
### Cisco Defense Orcestrator API Key
This module is for interacting with the Cisco Defense Orcestrator (CDO) platform and as such the module requires a CDO API key for each CDO tenant in which the user wishes to operate.

## Included content
<!--start collection content-->
### Cliconf plugins
Name | Description
--- | ---


### Modules
Name | Description
--- | ---
<!--end collection content-->
   
## Installing this collection
You can install the Cisco CDO collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install cisco.cdo
    
You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: cisco.cdo
```

## Contributing to this collection
We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Cisco ASA collection repository](https://github.com/ansible-collections/cisco.asa). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release notes
<!--Add a link to a changelog.md file or an external docsite to cover this information. -->
Release notes are available [here](https://github.com/ansible-collections/cisco.cdo/blob/main/CHANGELOG.rst).

## Roadmap
<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->
## Licensing
GNU General Public License v3.0 or later.
See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Mathijs Westerhof (@mathijswesterhof)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: vault_policy_list
version_added: 6.2.0
author:
  - Mathijs Westerhof (@mathijswesterhof)
short_description: Get a list of policy names from HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Gets a list of policy names from HashiCorp Vault.
seealso:
  - name: Vault policies
    description: Documentation for Vault policies.
    link: https://developer.hashicorp.com/vault/docs/concepts/policies
extends_documentation_fragment:
options:
  type:
    description: Get a list of policies defined in Hashicorp Vault
    type: str
    default: acl
    choices:
      - acl
      - rgp
      - egp
'''

EXAMPLES = r'''
- name: 'Get a list of acl policies'
  community.hashi_vault.vault_policy_list:
    type: acl
'''

RETURN = r'''
raw:
  description: The raw result of the read against the given path.
  returned: success
  type: dict
  sample:
    auth: null
    data:
      policies:
        - policy_a
        - policy_b
        - default
        - root
    lease_duration: 2764800
    lease_id: ""
    renewable: false
    request_id: e99f145f-f02a-7073-1229-e3f191057a70
    warnings: null
    wrap_info: null
data:
  description: The C(data) field of raw result. This can also be accessed via C(raw.data).
  returned: success
  type: dict
  sample:
    policies:
      - policy_a
      - policy_b
      - default
      - root
policies:
  description: The C(data.policies) field of the raw result. This is the list variant of C(data) in the return values.
  returned: success
  type: list
  sample:
    - policy_a
    - policy_b
    - default
    - root
'''

import traceback

from ansible.module_utils._text import to_native

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        type=dict(type='str', default='acl', choices=['acl', 'rgp', 'egp']),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    policy_type = module.params.get('type')
    path = f'sys/policies/{policy_type}'
    # Do note! there is a difference in output between sys/policy and sys/policies/acl where the first returns duplicate data under various keys

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)
    hvac_exceptions = module.helper.get_hvac().exceptions

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    try:
        raw = client.list(path)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(msg="Forbidden: Permission Denied to path ['%s']." % path, exception=traceback.format_exc())

    data = raw['data']
    policies = data['keys']
    module.exit_json(raw=raw, data=data, policies=policies)


def main():
    run_module()


if __name__ == '__main__':
    main()

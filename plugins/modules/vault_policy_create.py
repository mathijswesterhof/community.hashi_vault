#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Mathijs Westerhof (@Resdac)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_entity
  version_added: 5.0.0
  author:
    - Mathijs Westerhof (@Resdac)
  short_description: Creating or updating a policy
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:

"""

EXAMPLES = """
"""

RETURN = """
data:
  description: The raw result of the write against the given path.
  returned: success
  type: dict
"""

import traceback

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError

try:
    import hvac
except ImportError:
    HAS_HVAC = False
    HVAC_IMPORT_ERROR = traceback.format_exc()
else:
    HVAC_IMPORT_ERROR = None
    HAS_HVAC = True

def simple_sting_compare(string1, string2):
    lines1 = string1.splitlines(keepends=True)
    lines2 = string2.splitlines(keepends=True)
    diff = []
    for i in range(max(len(lines1), len(lines2))):
        if i >= len(lines1):
            diff.append(f'+ {lines2[i]}')
        elif i >= len(lines2):
            diff.append(f'- {lines1[i]}')
        elif lines1[i] != lines2[i]:
            diff.append(f'- {lines1[i]}')
            diff.append(f'+ {lines2[i]}')
    return ''.join(diff)
def run_module():
    """Get a policy from vault"""
    # POST /sys/policy/:name -> str

    argspec = HashiVaultModule.generate_argspec(
        name=dict(type='str', required=True),
        policy=dict(type='str', required=True),
        blind_check=dict(type='bool', default=True), # always returns true without checking if there would be a change
        check_mode=dict(type='bool', default=True), # value returned when check mode is active
        override_existing=dict(type='bool', default=True) # acts as update, if False only non-existing policies will be created
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR
        )

    name = module.params.get('name')
    new_policy = module.params.get('policy')
    check_mode = module.params.get('check_mode')
    blind_check = module.params.get('blind_check')
    override_existing =  module.params.get('override_existing')
    changed = False

    if module.check_mode and blind_check:
        # Exit before an auth is needed
        module.exit_json(changed=check_mode, data={})

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    try:
        raw = client.sys.read_policy(name=name)

        #NOTE 404 when does not exist...
        #     204 on post no data


        policy = raw['data']['rules']
        diff = simple_sting_compare(policy, new_policy)
        if diff:
            # there are changes, print them
            changed = True
        else:
            pass






    except hvac.exceptions.Forbidden:
        module.fail_json(msg="Forbidden: Permission Denied to policy '%s'." % name, exception=traceback.format_exc())
    except hvac.exceptions.InternalServerError as e:
        module.fail_json(msg="Internal Server Error: %s" % to_native(e), exception=traceback.format_exc())

    module.exit_json(changed=changed, policy=, raw=)
def main():
    run_module()


if __name__ == '__main__':
    main()



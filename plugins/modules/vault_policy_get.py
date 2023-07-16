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
  short_description: Reading a policy
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

def run_module():
    """Get a policy from vault"""
    # GET /sys/policy/:name -> str

    argspec = HashiVaultModule.generate_argspec(
        name=dict(type='str', required=True),
        ignore_missing=dict(type='bool', default=True)
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
    ignore_missing = module.params.get('ignore_missing')

    if module.check_mode:
        # Exit before an auth is needed
        module.exit_json(changed=False, data={})

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
        # (name, rules, request_id, lease_id, renewable, lease_duration, data, warnings, auth and wrap_info are shown)
        module.exit_json(changed=False, policy=raw['data']['rules'], raw=raw)


    except hvac.exceptions.Forbidden:
        module.fail_json(msg="Forbidden: Permission Denied to policy '%s'." % name, exception=traceback.format_exc())
    except hvac.exceptions.InvalidPath:
        if not ignore_missing:
            module.fail_json(msg="The policy '%s' doesn't seem to exist." % name, exception=traceback.format_exc())
        else:
            module.exit_json(changed=False, data={}, raw={})
    except hvac.exceptions.InternalServerError as e:
        module.fail_json(msg="Internal Server Error: %s" % to_native(e), exception=traceback.format_exc())

def main():
    run_module()


if __name__ == '__main__':
    main()

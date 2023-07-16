#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Mathijs Westerhof (@Resdac)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_delete
  version_added: 5.0.0
  author:
    - Mathijs Westerhof (@Resdac)
  short_description: Perform a delete operation against HashiCorp Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Performs a generic delete operation against a given path in HashiCorp Vault, returning any output.
  notes:
    - C(vault_delete) is a generic module to do operations that do not yet have a dedicated module. Where a specific module exists, that should be used instead.
    - This module always reports C(changed) status because it cannot guarantee idempotence.
    - Use C(changed_when) to control that in cases where the operation is known to not change state.
  attributes:
    check_mode:
      support: partial
      details:
        - In check mode, an empty response will be returned and the delete will not be performed.
  seealso:
    - module: community.hashi_vault.vault_delete
  extends_documentation_fragment:
    - community.hashi_vault.attributes
    - community.hashi_vault.attributes.action_group
    - community.hashi_vault.connection
    - community.hashi_vault.auth
    - community.hashi_vault.wrapping
  options:
    path:
      description: Vault path to be written to.
      type: str
      required: True
"""

EXAMPLES = """
- name: delete a group via the remote host with userpass auth
  community.hashi_vault.vault_delete:
    url: https://vault:8201
    path: identity/group/name/{{ group_name }}
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: result

- name: Display the result of the delete (this can be empty)
  ansible.builtin.debug:
    msg: "{{ result.data }}"

- name: Delete by token
  community.hashi_vault.vault_delete:
    token: "{{ login | community.hashi_vault.vault_login_token }}"
    path: identity/entity-alias/user_1_alias
"""

RETURN = """
data:
  description: The raw result of the delete against the given path.
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
    argspec = HashiVaultModule.generate_argspec(
        path=dict(type='str', required=True)
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

    path = module.params.get('path')

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    try:
        if module.check_mode:
            response = {}
        else:
            response = client.delete(path=path)
    except hvac.exceptions.Forbidden:
        module.fail_json(msg="Forbidden: Permission Denied to path '%s'." % path, exception=traceback.format_exc())
    except hvac.exceptions.InvalidPath:
        module.fail_json(msg="The path '%s' doesn't seem to exist." % path, exception=traceback.format_exc())
    except hvac.exceptions.InternalServerError as e:
        module.fail_json(msg="Internal Server Error: %s" % to_native(e), exception=traceback.format_exc())

    # https://github.com/hvac/hvac/issues/797
    # HVAC returns a raw response object when the body is not JSON.
    # That includes 204 responses, which are successful with no body.
    # So we will try to detect that and a act accordingly.
    # A better way may be to implement our own adapter for this
    # collection, but it's a little premature to do that.
    if hasattr(response, 'json') and callable(response.json):
        if response.status_code == 204:
            output = {}
        else:
            module.warn('Vault returned status code %i and an unparsable body.' % response.status_code)
            output = response.content
    else:
        output = response

    module.exit_json(changed=True, data=output)


def main():
    run_module()


if __name__ == '__main__':
    main()

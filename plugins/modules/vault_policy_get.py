#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Mathijs Westerhof (@mathijswesterhof)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: vault_policy_get
version_added: 6.2.0
author:
  - Mathijs Westerhof (@mathijswesterhof)
short_description: Get a policy or policy-list from HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Gets a policy or policy-list from HashiCorp Vault.
seealso:
  - name: Vault policies
    description: Documentation for Vault policies.
    link: https://developer.hashicorp.com/vault/docs/concepts/policies
extends_documentation_fragment:
options:
'''

EXAMPLES = r'''
'''

RETURN = r'''
raw:
data:
secret:
metadata:
'''

import traceback

from ansible.module_utils._text import to_native

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    module.exit_json()


def main():
    run_module()


if __name__ == '__main__':
    main()

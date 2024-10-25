# -*- coding: utf-8 -*-
# Copyright (c) 2024 Mathijs Westerhof (@mathijswesterhof)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest

from .....plugins.modules import vault_policy_delete
from .....plugins.module_utils._hashi_vault_common import HashiVaultValueError


hvac = pytest.importorskip('hvac')


class TestModuleVaultPolicyDelete():
    # happy flow
    def test_vault_policy_delete_acl(self):
        pass

    def test_vault_policy_delete_non_present_acl(self):
        pass

    def test_vault_policy_delete_rgp(self):
        pass

    def test_vault_policy_delete_non_present_rgp(self):
        pass

    def test_vault_policy_delete_egp(self):
        pass

    def test_vault_policy_delete_non_present_egp(self):
        pass

    # unhappy flow
    def test_vault_policy_delete_hvac_error(self):
        pass

    def test_vault_policy_delete_auth_error(self):
        pass

    def test_vault_policy_delete_access_error(self):
        pass

    def test_vault_policy_delete_unknown_policy_type_error(self):
        pass

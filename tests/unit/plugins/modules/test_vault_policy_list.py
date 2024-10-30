# -*- coding: utf-8 -*-
# Copyright (c) 2024 Mathijs Westerhof (@mathijswesterhof)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest

from .....plugins.modules import vault_policy_list
from .....plugins.module_utils._hashi_vault_common import HashiVaultValueError


hvac = pytest.importorskip('hvac')


def _connection_options():
    return {
        'auth_method': 'token',
        'url': 'http://myvault',
        'token': 'beep-boop',
    }


def _combined_options(**kwargs):
    opt = _connection_options()
    opt.update(kwargs)
    return opt

LIST_FIXTURES = [
    'policy_list_response.json',
]


@pytest.fixture(params=LIST_FIXTURES)
def list_response(request, fixture_loader):
    return fixture_loader(request.param)


class TestModuleVaultPolicyList():
    # happy flow
    def test_vault_policy_list_get_return_empty_acl(self):
        pass

    @pytest.mark.parametrize('patch_ansible_module', [_combined_options(type='acl')], indirect=True)
    def test_vault_policy_list_get_return_data_acl(self, patch_ansible_module, list_response, vault_client, capfd):
        client = vault_client
        client.list.return_value = list_response.copy()

        with pytest.raises(SystemExit) as e:
            vault_policy_list.main()

        out, err = capfd.readouterr()
        result = json.loads(out)

        assert e.value.code == 0, "result: %r" % (result,)

        client.list.assert_called_once_with(patch_ansible_module['path'])

        assert result[
                   'data'] == list_response, "module result did not match expected result:\nexpected: %r\ngot: %r" % (
        list_response, result)

    def test_vault_policy_list_get_return_empty_rgp(self):
        pass

    def test_vault_policy_list_get_return_data_rgp(self):
        pass

    def test_vault_policy_list_get_return_empty_egp(self):
        pass

    def test_vault_policy_list_get_return_data_egp(self):
        pass

    # unhappy flow
    def test_vault_policy_list_hvac_error(self):
        pass

    def test_vault_policy_list_auth_error(self):
        pass

    def test_vault_policy_list_access_error(self):
        pass

    def test_vault_policy_list_unknown_policy_type_error(self):
        pass

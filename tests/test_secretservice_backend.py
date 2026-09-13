"""
Tests for the provider-agnostic Secret Service backend.

Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from unittest import mock

import keyring
import pytest
import secretstorage

from proton.keyring_linux.secretservice import secretservice_backend
from proton.keyring_linux.secretservice.secretservice_backend import (
    KeyringBackendLinuxSecretService,
)


def test_validate_checks_availability_without_reading_a_secret(monkeypatch):
    backend = mock.Mock(priority=5)
    get_backend = mock.Mock(return_value=backend)
    monkeypatch.delenv("SNAP", raising=False)
    monkeypatch.setattr(
        secretservice_backend, "_get_secret_service_backend", get_backend
    )

    assert KeyringBackendLinuxSecretService._validate()
    get_backend.assert_called_once_with()
    backend.get_password.assert_not_called()


def test_validate_rejects_unavailable_secret_service(monkeypatch):
    monkeypatch.delenv("SNAP", raising=False)
    monkeypatch.setattr(
        secretservice_backend,
        "_get_secret_service_backend",
        mock.Mock(side_effect=RuntimeError("not owned or activatable")),
    )

    assert not KeyringBackendLinuxSecretService._validate()


def test_default_collection_is_preferred():
    backend = secretservice_backend._get_secret_service_backend()
    secretstorage_module = mock.Mock()
    connection = mock.sentinel.connection
    default_collection = mock.sentinel.default_collection
    secretstorage_module.get_collection_by_alias.return_value = default_collection

    result = backend._get_default_or_only_collection(
        secretstorage_module, connection
    )

    assert result is default_collection
    secretstorage_module.get_collection_by_alias.assert_called_once_with(
        connection, "default"
    )
    secretstorage_module.get_all_collections.assert_not_called()


def test_only_collection_is_used_when_default_alias_is_stale():
    backend = secretservice_backend._get_secret_service_backend()
    secretstorage_module = mock.Mock()
    secretstorage_module.exceptions.ItemNotFoundException = type(
        "ItemNotFoundException", (Exception,), {}
    )
    secretstorage_module.get_collection_by_alias.side_effect = (
        secretstorage_module.exceptions.ItemNotFoundException()
    )
    collection = mock.sentinel.collection
    secretstorage_module.get_all_collections.return_value = iter([collection])

    result = backend._get_default_or_only_collection(
        secretstorage_module, mock.sentinel.connection
    )

    assert result is collection
    secretstorage_module.create_collection.assert_not_called()


def test_empty_service_may_create_a_default_collection():
    backend = secretservice_backend._get_secret_service_backend()
    secretstorage_module = mock.Mock()
    secretstorage_module.exceptions.ItemNotFoundException = type(
        "ItemNotFoundException", (Exception,), {}
    )
    secretstorage_module.get_collection_by_alias.side_effect = (
        secretstorage_module.exceptions.ItemNotFoundException()
    )
    secretstorage_module.get_all_collections.return_value = iter([])
    created_collection = mock.sentinel.created_collection
    secretstorage_module.create_collection.return_value = created_collection
    connection = mock.sentinel.connection

    result = backend._get_default_or_only_collection(
        secretstorage_module, connection
    )

    assert result is created_collection
    secretstorage_module.create_collection.assert_called_once_with(
        connection, "Default", "default"
    )


def test_multiple_collections_without_default_are_rejected():
    backend = secretservice_backend._get_secret_service_backend()
    secretstorage_module = mock.Mock()
    secretstorage_module.exceptions.ItemNotFoundException = type(
        "ItemNotFoundException", (Exception,), {}
    )
    secretstorage_module.get_collection_by_alias.side_effect = (
        secretstorage_module.exceptions.ItemNotFoundException()
    )
    secretstorage_module.get_all_collections.return_value = iter(
        [mock.sentinel.first, mock.sentinel.second]
    )

    with pytest.raises(keyring.errors.InitError, match="multiple collections"):
        backend._get_default_or_only_collection(
            secretstorage_module, mock.sentinel.connection
        )

    secretstorage_module.create_collection.assert_not_called()


def test_connection_is_reused_across_secret_reads(monkeypatch):
    backend = secretservice_backend._get_secret_service_backend()
    connection = mock.Mock()
    monkeypatch.setattr(
        secretstorage, "dbus_init", mock.Mock(return_value=connection)
    )
    collection = mock.Mock()
    collection.is_locked.return_value = False
    first_item = mock.Mock()
    first_item.is_locked.return_value = False
    first_item.get_secret.return_value = b"first"
    second_item = mock.Mock()
    second_item.is_locked.return_value = False
    second_item.get_secret.return_value = b"second"
    collection.search_items.side_effect = [iter([first_item]), iter([second_item])]
    monkeypatch.setattr(
        backend,
        "_get_default_or_only_collection",
        mock.Mock(return_value=collection),
    )

    assert backend.get_password("Proton", "first") == "first"
    assert backend.get_password("Proton", "second") == "second"

    secretstorage.dbus_init.assert_called_once_with()
    assert backend._get_default_or_only_collection.call_count == 2
    assert all(
        call.args == (secretstorage, connection)
        for call in backend._get_default_or_only_collection.call_args_list
    )
    connection.close.assert_not_called()

    backend.close()
    connection.close.assert_called_once_with()


def test_closed_backend_opens_a_new_connection_on_next_operation(monkeypatch):
    backend = secretservice_backend._get_secret_service_backend()
    first_connection = mock.Mock()
    second_connection = mock.Mock()
    monkeypatch.setattr(
        secretstorage,
        "dbus_init",
        mock.Mock(side_effect=[first_connection, second_connection]),
    )
    collection = mock.Mock()
    collection.is_locked.return_value = False
    monkeypatch.setattr(
        backend,
        "_get_default_or_only_collection",
        mock.Mock(return_value=collection),
    )

    backend.get_preferred_collection()
    backend.close()
    backend.get_preferred_collection()
    backend.close()

    assert secretstorage.dbus_init.call_count == 2
    first_connection.close.assert_called_once_with()
    second_connection.close.assert_called_once_with()


def test_get_credential_does_not_close_persistent_connection(monkeypatch):
    backend = secretservice_backend._get_secret_service_backend()
    connection = mock.Mock()
    monkeypatch.setattr(
        secretstorage, "dbus_init", mock.Mock(return_value=connection)
    )
    collection = mock.Mock()
    collection.is_locked.return_value = False
    item = mock.Mock()
    item.is_locked.return_value = False
    item.get_attributes.return_value = {"username": "alice"}
    item.get_secret.return_value = b"secret"
    collection.search_items.return_value = iter([item])
    monkeypatch.setattr(
        backend,
        "_get_default_or_only_collection",
        mock.Mock(return_value=collection),
    )

    credential = backend.get_credential("Proton", "alice")

    assert credential.username == "alice"
    assert credential.password == "secret"
    connection.close.assert_not_called()
    backend.close()
    connection.close.assert_called_once_with()


def test_write_and_delete_reuse_persistent_connection(monkeypatch):
    backend = secretservice_backend._get_secret_service_backend()
    connection = mock.Mock()
    monkeypatch.setattr(
        secretstorage, "dbus_init", mock.Mock(return_value=connection)
    )
    collection = mock.Mock()
    collection.is_locked.return_value = False
    item = mock.Mock()
    collection.search_items.return_value = iter([item])
    monkeypatch.setattr(
        backend,
        "_get_default_or_only_collection",
        mock.Mock(return_value=collection),
    )

    backend.set_password("Proton", "alice", "secret")
    backend.delete_password("Proton", "alice")

    secretstorage.dbus_init.assert_called_once_with()
    collection.create_item.assert_called_once()
    item.delete.assert_called_once_with()
    connection.close.assert_not_called()
    backend.close()
    connection.close.assert_called_once_with()

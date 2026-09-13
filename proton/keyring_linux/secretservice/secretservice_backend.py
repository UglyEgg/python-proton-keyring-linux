"""Module for Linux Secret Service Keyring backend.


Copyright (c) 2023 Proton AG

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
import json
import logging
import os
import threading
import weakref

import keyring
from keyring.credentials import SimpleCredential
from proton.keyring.exceptions import KeyringLocked, KeyringError
from proton.keyring_linux.core import KeyringBackendLinux

logger = logging.getLogger(__name__)


def _get_secret_service_backend():
    """Return Python Keyring's Secret Service backend with safer collection lookup."""
    # pylint: disable=import-outside-toplevel
    import secretstorage
    from keyring.backends import SecretService

    class ProviderAgnosticSecretServiceKeyring(SecretService.Keyring):
        """Secret Service backend with provider-agnostic collection handling.

        A Secret Service client is identified by its unique D-Bus connection.
        Keep one connection for the lifetime of this backend so providers can
        remember authorization decisions across multiple keyring operations.
        """

        def __init__(self):
            super().__init__()
            self._connection = None
            self._connection_finalizer = None
            self._operation_lock = threading.RLock()

        def _get_connection(self):
            if self._connection is None:
                self._connection = secretstorage.dbus_init()
                self._connection_finalizer = weakref.finalize(
                    self, self._connection.close
                )
            return self._connection

        def close(self):
            """Close the persistent D-Bus connection, if it was opened."""
            with self._operation_lock:
                if (
                    self._connection_finalizer is not None
                    and self._connection_finalizer.alive
                ):
                    self._connection_finalizer()
                self._connection = None
                self._connection_finalizer = None

        def get_preferred_collection(self):
            connection = self._get_connection()
            try:
                if hasattr(self, "preferred_collection"):
                    collection = secretstorage.Collection(
                        connection, self.preferred_collection
                    )
                else:
                    collection = self._get_default_or_only_collection(
                        secretstorage, connection
                    )
            except secretstorage.exceptions.SecretStorageException as excp:
                raise keyring.errors.InitError(
                    f"Failed to get a Secret Service collection: {excp}."
                ) from excp

            if collection.is_locked():
                collection.unlock()
                if collection.is_locked():
                    raise keyring.errors.KeyringLocked(
                        "Failed to unlock the collection!"
                    )
            return collection

        def get_password(self, service, username):
            """Get a password without discarding the D-Bus client identity."""
            with self._operation_lock:
                collection = self.get_preferred_collection()
                items = collection.search_items(self._query(service, username))
                for item in items:
                    self.unlock(item)
                    return item.get_secret().decode("utf-8")
            return None

        def set_password(self, service, username, password):
            """Set a password using the persistent D-Bus connection."""
            with self._operation_lock:
                collection = self.get_preferred_collection()
                attributes = self._query(
                    service, username, application=self.appid
                )
                label = f"Password for '{username}' on '{service}'"
                collection.create_item(
                    label, attributes, password, replace=True
                )

        def delete_password(self, service, username):
            """Delete a password using the persistent D-Bus connection."""
            with self._operation_lock:
                collection = self.get_preferred_collection()
                items = collection.search_items(self._query(service, username))
                for item in items:
                    return item.delete()
            raise keyring.errors.PasswordDeleteError("No such password!")

        def get_credential(self, service, username):
            """Get a credential using the persistent D-Bus connection."""
            with self._operation_lock:
                scheme = self.schemes[self.scheme]
                query = self._query(service, username)
                collection = self.get_preferred_collection()
                items = collection.search_items(query)
                for item in items:
                    self.unlock(item)
                    item_username = item.get_attributes().get(
                        scheme["username"]
                    )
                    return SimpleCredential(
                        item_username, item.get_secret().decode("utf-8")
                    )
            return None

        @staticmethod
        def _get_default_or_only_collection(secretstorage_module, connection):
            try:
                return secretstorage_module.get_collection_by_alias(
                    connection, "default"
                )
            except secretstorage_module.exceptions.ItemNotFoundException:
                collections = list(
                    secretstorage_module.get_all_collections(connection)
                )

                if len(collections) == 1:
                    logger.warning(
                        "The default Secret Service collection alias is unavailable; "
                        "using the only advertised collection"
                    )
                    return collections[0]

                if not collections:
                    return secretstorage_module.create_collection(
                        connection, "Default", "default"
                    )

                raise keyring.errors.InitError(
                    "The default Secret Service collection alias is unavailable "
                    "and the provider advertises multiple collections"
                )

    return ProviderAgnosticSecretServiceKeyring()


# pylint: disable=too-few-public-methods
class KeyringBackendLinuxSecretService(KeyringBackendLinux):
    """Implements the Secret Service keyring backend."""
    @classmethod
    def _get_priority(cls):
        return 5.

    @classmethod
    def _validate(cls):
        # this keyring doesn't work with snap containment
        if os.environ.get("SNAP") is not None:
            return False
        try:
            # Python Keyring's priority check verifies that SecretStorage is
            # installed and org.freedesktop.secrets is owned or activatable.
            # Do not probe with get_password(): that requires a usable default
            # collection and can create one as a side effect.
            return _get_secret_service_backend().priority > 0
        except (ModuleNotFoundError, RuntimeError):
            logger.debug("Secret Service backend not available", exc_info=True)
            return False

    def __init__(self):
        self._backend = _get_secret_service_backend()
        super().__init__(self._backend)

    def _get_item(self, key):
        try:
            stored_data = self._backend.get_password(
                self.KEYRING_SERVICE,
                key
            )
        except keyring.errors.KeyringLocked as excp:
            logging.info("Keyring locked while getting")
            raise KeyringLocked("Keyring is locked") from excp
        except keyring.errors.KeyringError as excp:
            logging.exception("Keyring error while getting")
            raise KeyringError(excp) from excp

        # Since we're borrowing the dict interface,
        # be consistent and throw a KeyError if it doesn't exist
        if stored_data is None:
            raise KeyError(key)

        try:
            return json.loads(stored_data)
        except json.JSONDecodeError:
            # gnome-keyring has a bug when processing new lines.
            # Anytime we store the data to the keyring, we store all newlines in
            # escaped form, aka \\n. For some reason, when gnome-keyring has no password
            # set, upon reading from the keyring it seems auto-escape the string and the
            # output becomes \n thus, treating this as a literal new line character,
            # causing a crash when we try to load the string via json, because again, \n are
            # treated literally. On the contrary, when the keyring has a password set,
            # and when we retrieve the data from the keyring, the new lines are properly
            # escaped and thus it does not crash once we try to load the string to json format.
            # From out testing, both via secret-storage and libsecret packages
            # (and even secret-tool) we were able to recreate this issue, thus indicating that
            # the issue is with gnome-keyring and not related to packages that
            # communicate with the gnome-keyring.
            # See more at:
            # https://discourse.gnome.org/t/possible-bug-or-feature-storing-getting-data-keyring-protected-vs-unprotected-keyring/20312

            # This fixed was found by Wizzerinus on GitHub and a PR was create by Anonymous941
            # https://github.com/ProtonVPN/python-proton-keyring-linux/pull/1

            stored_data = stored_data.replace("\n", "\\n")

        try:
            return json.loads(stored_data)
        except json.JSONDecodeError as excp:
            # Something is wrong here, delete data (it's invalid anyway)
            logging.exception("Keyring credential is not valid JSON, deleting")
            self._del_item(key)
            raise KeyError(key) from excp

# Copyright (c) 2025 Dave Mobley.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""This module contains the credential management functionality for PowerFlex."""

import logging
from PyPowerFlex import base_client
from PyPowerFlex import exceptions

LOG = logging.getLogger(__name__)


class CredentialType:
    """Credential types supported by PowerFlex."""

    HOST = "Host"
    STORAGE = "Storage"
    MANAGEMENT = "Management"


class Credential(base_client.EntityRequest):
    """
    Class for managing PowerFlex credentials.
    """
    entity = "Credential"

    def __init__(self, token, configuration):
        super().__init__(token, configuration)
        self._validate_version()

    def _validate_version(self):
        """Validate that the PowerFlex version supports credential management."""
        version = self.get_api_version()
        if version < "3.0":
            raise exceptions.PowerFlexClientException(
                "Credential management is not supported in PowerFlex versions below 3.0"
            )

    def get_credential_details(self, credential_id):
        """Get details of a specific credential.

        :type credential_id: str
        :rtype: dict
        """
        return self.get(entity_id=credential_id)

    def list_credentials(self, filter_fields=None, fields=None):
        """Get a list of credentials.

        :type filter_fields: dict
        :type fields: list|tuple
        :rtype: list[dict]
        """
        return self.get_all(filter_fields=filter_fields, fields=fields)

    def add_credential(self, credential_type, username, password, **kwargs):
        """Add a new credential.

        :type credential_type: str
        :type username: str
        :type password: str
        :type kwargs: dict
        :rtype: dict
        """
        if credential_type not in [CredentialType.HOST, CredentialType.STORAGE, CredentialType.MANAGEMENT]:
            raise exceptions.PowerFlexInvalidCredentialType(credential_type)

        params = {
            "credentialType": credential_type,
            "username": username,
            "password": password,
            **kwargs
        }

        return self._create_entity(params)

    def update_credential(self, credential_id, **kwargs):
        """Update an existing credential.

        :type credential_id: str
        :type kwargs: dict
        :rtype: dict
        """
        # First verify the credential exists
        try:
            existing = self.get_credential_details(credential_id)
        except exceptions.PowerFlexFailQuerying:
            raise exceptions.PowerFlexCredentialNotFound(credential_id)

        # Preserve the credential type
        if "credentialType" in kwargs:
            del kwargs["credentialType"]

        params = {
            "credentialType": existing["credentialType"],
            **kwargs
        }

        return self._update_entity(credential_id, params)

    def delete_credential(self, credential_id):
        """Delete a credential.

        :type credential_id: str
        :rtype: None
        """
        return self._delete_entity(credential_id)
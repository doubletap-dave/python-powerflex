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
import time
from requests.exceptions import Timeout
from PyPowerFlex import base_client
from PyPowerFlex import exceptions
from PyPowerFlex import constants

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
        # Version validation is handled by the base client
        self._validate_gateway_vs_manager()

    def _validate_gateway_vs_manager(self):
        """Validate that we're connected to a PowerFlex Manager and not a Gateway.
        
        This method attempts to access the credentials endpoint. If a 404 response
        is received, it indicates we're connected to a Gateway which doesn't support
        credential operations.
        
        :raises: PowerFlexFailCredentialOperation if connected to a Gateway
        """
        try:
            # Attempt to access credentials endpoint
            response = self.send_request(self.GET, '/credentials')
            if response.status_code == 404:
                LOG.error("Credential operations are not supported on Gateway connections")
                raise exceptions.PowerFlexFailCredentialOperation(
                    "Credential operations are not supported on Gateway connections"
                )
        except exceptions.PowerFlexClientException as e:
            # If we get a 404, it means we're on a Gateway
            if hasattr(e, 'status_code') and e.status_code == 404:
                LOG.error("Credential operations are not supported on Gateway connections")
                raise exceptions.PowerFlexFailCredentialOperation(
                    "Credential operations are not supported on Gateway connections"
                )
            # Re-raise other exceptions
            raise

    def _validate_xml_structure(self, xml_data):
        """Validate the XML structure of credential data.
        
        :type xml_data: dict
        :raises: PowerFlexClientException if XML structure is invalid
        """
        if not isinstance(xml_data, dict):
            raise exceptions.PowerFlexClientException("Invalid XML structure: expected dict")
        
        for field, field_type in constants.CredentialConstants.REQUIRED_FIELDS.items():
            if field not in xml_data:
                raise exceptions.PowerFlexClientException(f"Missing required field: {field}")
            if not isinstance(xml_data[field], field_type):
                raise exceptions.PowerFlexClientException(
                    f"Invalid type for field {field}: expected {field_type.__name__}"
                )

    def _validate_field_lengths(self, data):
        """Validate field lengths in credential data.
        
        :type data: dict
        :raises: PowerFlexClientException if field lengths are invalid
        """
        if "username" in data and len(data["username"]) > constants.CredentialConstants.MAX_USERNAME_LENGTH:
            raise exceptions.PowerFlexClientException(
                f"Username exceeds maximum length of {constants.CredentialConstants.MAX_USERNAME_LENGTH}"
            )
        if "password" in data and len(data["password"]) > constants.CredentialConstants.MAX_PASSWORD_LENGTH:
            raise exceptions.PowerFlexClientException(
                f"Password exceeds maximum length of {constants.CredentialConstants.MAX_PASSWORD_LENGTH}"
            )

    def _sanitize_input(self, data):
        """Sanitize input data to prevent XML injection.
        
        :type data: dict
        :rtype: dict
        """
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Replace XML special characters
                sanitized[key] = (value.replace("&", "&amp;")
                                .replace("<", "&lt;")
                                .replace(">", "&gt;")
                                .replace('"', "&quot;")
                                .replace("'", "&apos;"))
            else:
                sanitized[key] = value
        return sanitized

    def _handle_timeout(self, operation, retry_count=0):
        """Handle timeout errors with retry logic.
        
        :type operation: str
        :type retry_count: int
        :raises: PowerFlexClientException if max retries exceeded
        """
        if retry_count >= constants.CredentialConstants.MAX_RETRIES:
            raise exceptions.PowerFlexClientException(
                f"Operation {operation} timed out after {constants.CredentialConstants.MAX_RETRIES} retries"
            )
        
        LOG.warning(
            f"Operation {operation} timed out. Retrying in {constants.CredentialConstants.RETRY_DELAY} seconds... "
            f"(Attempt {retry_count + 1}/{constants.CredentialConstants.MAX_RETRIES})"
        )
        time.sleep(constants.CredentialConstants.RETRY_DELAY)

    def _execute_with_retry(self, operation, func, *args, **kwargs):
        """Execute a function with retry logic for timeout errors.
        
        :type operation: str
        :type func: callable
        :type args: tuple
        :type kwargs: dict
        :rtype: Any
        """
        retry_count = 0
        while True:
            try:
                return func(*args, **kwargs)
            except Timeout:
                retry_count += 1
                self._handle_timeout(operation, retry_count)

    def get_credential_details(self, credential_id):
        """Get details of a specific credential.

        :type credential_id: str
        :rtype: dict
        """
        return self._execute_with_retry(
            "get_credential_details",
            super().get,
            entity_id=credential_id
        )

    def list_credentials(self, filter_fields=None, fields=None):
        """Get a list of credentials.

        :type filter_fields: dict
        :type fields: list|tuple
        :rtype: list[dict]
        """
        return self._execute_with_retry(
            "list_credentials",
            super().get_all,
            filter_fields=filter_fields,
            fields=fields
        )

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

        # Validate and sanitize input
        self._validate_xml_structure(params)
        self._validate_field_lengths(params)
        params = self._sanitize_input(params)

        return self._execute_with_retry(
            "add_credential",
            self._create_entity,
            params=params
        )

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

        # Validate and sanitize input
        self._validate_field_lengths(params)
        params = self._sanitize_input(params)

        return self._execute_with_retry(
            "update_credential",
            self._update_entity,
            credential_id,
            params=params
        )

    def delete_credential(self, credential_id):
        """Delete a credential.

        :type credential_id: str
        :rtype: None
        """
        return self._execute_with_retry(
            "delete_credential",
            self._delete_entity,
            credential_id
        )
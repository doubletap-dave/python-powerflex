# Copyright (c) 2024 Dell Inc. or its subsidiaries.
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

"""Module for testing credential client."""

# pylint: disable=invalid-name,too-many-public-methods

from PyPowerFlex import exceptions
from PyPowerFlex.objects import credential
import tests


class TestCredentialClient(tests.PyPowerFlexTestCase):
    """
    Test class for the credential client.
    """

    def setUp(self):
        """
        Set up the test case.
        """
        super().setUp()
        self.client.initialize()
        self.fake_credential_id = 'c0de1100-f00d-dead-beefcafe133742'
        self.fake_username = 'test_user'
        self.fake_password = 'test_password'

        self.MOCK_RESPONSES = {
            self.RESPONSE_MODE.Valid: {
                '/types/Credential/instances':
                    {'id': self.fake_credential_id},
                f'/instances/Credential::{self.fake_credential_id}':
                    {'id': self.fake_credential_id},
                '/credentials':
                    {'id': self.fake_credential_id},
                '/types/Credential':
                    {'id': self.fake_credential_id},
            },
            self.RESPONSE_MODE.Invalid: {
                '/credentials': {},
            },
            self.RESPONSE_MODE.NotFound: {
                '/credentials': {},
            }
        }

    def test_credential_create(self):
        """
        Test if credential create is successful.
        """
        self.client.credential.create(
            username=self.fake_username,
            password=self.fake_password,
            credential_type=credential.CredentialType.SDC
        )

    def test_credential_create_bad_status(self):
        """
        Test if credential create raises an exception when the HTTP status is bad.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            self.assertRaises(exceptions.PowerFlexFailCreating,
                            self.client.credential.create,
                            username=self.fake_username,
                            password=self.fake_password,
                            credential_type=credential.CredentialType.SDC)

    def test_credential_create_invalid_type(self):
        """
        Test if credential create raises an exception with invalid credential type.
        """
        with self.assertRaises(exceptions.PowerFlexInvalidCredentialType):
            self.client.credential.create(
                username=self.fake_username,
                password=self.fake_password,
                credential_type='invalid_type'
            )

    def test_credential_create_missing_fields(self):
        """
        Test if credential create raises an exception with missing required fields.
        """
        with self.assertRaises(exceptions.InvalidInput):
            self.client.credential.create(
                username=self.fake_username,
                credential_type=credential.CredentialType.SDC
            )

    def test_credential_get_details(self):
        """
        Test if credential get details is successful.
        """
        self.client.credential.get_details(self.fake_credential_id)

    def test_credential_get_details_bad_status(self):
        """
        Test if credential get details raises an exception when the HTTP status is bad.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            self.assertRaises(exceptions.PowerFlexClientException,
                            self.client.credential.get_details,
                            self.fake_credential_id)

    def test_credential_get_details_not_found(self):
        """
        Test if credential get details raises an exception when credential is not found.
        """
        with self.http_response_mode(self.RESPONSE_MODE.NotFound):
            self.assertRaises(exceptions.PowerFlexCredentialNotFound,
                            self.client.credential.get_details,
                            self.fake_credential_id)

    def test_credential_update(self):
        """
        Test if credential update is successful.
        """
        self.client.credential.update(
            self.fake_credential_id,
            password='new_password'
        )

    def test_credential_update_bad_status(self):
        """
        Test if credential update raises an exception when the HTTP status is bad.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            self.assertRaises(exceptions.PowerFlexClientException,
                            self.client.credential.update,
                            self.fake_credential_id,
                            password='new_password')

    def test_credential_update_not_found(self):
        """
        Test if credential update raises an exception when credential is not found.
        """
        with self.http_response_mode(self.RESPONSE_MODE.NotFound):
            self.assertRaises(exceptions.PowerFlexCredentialNotFound,
                            self.client.credential.update,
                            self.fake_credential_id,
                            password='new_password')

    def test_credential_delete(self):
        """
        Test if credential delete is successful.
        """
        self.client.credential.delete(self.fake_credential_id)

    def test_credential_delete_bad_status(self):
        """
        Test if credential delete raises an exception when the HTTP status is bad.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            self.assertRaises(exceptions.PowerFlexFailDeleting,
                            self.client.credential.delete,
                            self.fake_credential_id)

    def test_credential_delete_not_found(self):
        """
        Test if credential delete raises an exception when credential is not found.
        """
        with self.http_response_mode(self.RESPONSE_MODE.NotFound):
            self.assertRaises(exceptions.PowerFlexCredentialNotFound,
                            self.client.credential.delete,
                            self.fake_credential_id)

    def test_credential_list(self):
        """
        Test if credential list is successful.
        """
        self.client.credential.list()

    def test_credential_list_bad_status(self):
        """
        Test if credential list raises an exception when the HTTP status is bad.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            self.assertRaises(exceptions.PowerFlexClientException,
                            self.client.credential.list)

    def test_gateway_vs_manager_validation(self):
        """
        Test Gateway vs Manager validation.
        """
        # Test Manager connection (credentials endpoint exists)
        self.client.credential._validate_gateway_vs_manager()

        # Test Gateway connection (credentials endpoint returns 404)
        with self.http_response_mode(self.RESPONSE_MODE.NotFound):
            with self.assertRaises(exceptions.PowerFlexClientException) as error:
                self.client.credential._validate_gateway_vs_manager()
            self.assertIn('Gateway connection detected', str(error.exception))

    def test_xml_sanitization(self):
        """
        Test XML sanitization for special characters.
        """
        # Test with special characters in username
        self.client.credential.create(
            username='test&user',
            password=self.fake_password,
            credential_type=credential.CredentialType.SDC
        )

        # Test with special characters in password
        self.client.credential.create(
            username=self.fake_username,
            password='test&password',
            credential_type=credential.CredentialType.SDC
        )

    def test_password_handling(self):
        """
        Test secure password handling.
        """
        # Test password is not logged
        with self.assertLogs(level='DEBUG') as log:
            self.client.credential.create(
                username=self.fake_username,
                password=self.fake_password,
                credential_type=credential.CredentialType.SDC
            )
            self.assertNotIn(self.fake_password, str(log.output))

    def test_error_message_security(self):
        """
        Test error messages do not contain sensitive information.
        """
        with self.http_response_mode(self.RESPONSE_MODE.BadStatus):
            try:
                self.client.credential.create(
                    username=self.fake_username,
                    password=self.fake_password,
                    credential_type=credential.CredentialType.SDC
                )
            except exceptions.PowerFlexClientException as error:
                self.assertNotIn(self.fake_password, str(error))
                self.assertNotIn(self.fake_username, str(error))

    def test_timeout_handling(self):
        """
        Test timeout handling for credential operations.
        """
        with self.http_response_mode(self.RESPONSE_MODE.Timeout):
            self.assertRaises(exceptions.PowerFlexClientException,
                            self.client.credential.create,
                            username=self.fake_username,
                            password=self.fake_password,
                            credential_type=credential.CredentialType.SDC) 
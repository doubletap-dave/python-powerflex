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

"""Module for testing PowerFlex credential management."""

from unittest import mock

from PyPowerFlex import exceptions
from PyPowerFlex.objects.credential import (
    BaseCredential,
    ServerCredential,
    VCenterCredential,
    IomCredential,
    EmCredential,
    ScaleIOCredential,
    PSCredential,
    OSCredential,
    OSUserCredential
)
import tests


# pylint: disable=too-many-public-methods
# This test class needs comprehensive coverage of credential functionality
class TestPowerFlexCredential(tests.PyPowerFlexTestCase):
    """
    Test class for PowerFlex credential management.
    """

    def setUp(self):
        """
        Set up the test case.
        """
        super().setUp()

        # Initialize the mock_responses dictionary with the required structure
        self.MOCK_RESPONSES = {
            self.RESPONSE_MODE.Valid: {},
            self.RESPONSE_MODE.Invalid: {},
            self.RESPONSE_MODE.BadStatus: {}
        }

        # Set version to 4.0 before initializing client
        self.DEFAULT_MOCK_RESPONSES[self.RESPONSE_MODE.Valid]['/version'] = '4.0'

        self.client.initialize()

        # Mock responses for credential API operations
        self.MOCK_RESPONSES[self.RESPONSE_MODE.Valid].update({
            '/version': '4.0',
            '/Api/V1/Credential': {
                'credential': {
                    'id': 'd32c5fea-721b-446e-994d-1e0baf921b3a',
                    'label': 'Test Server',
                    'username': 'admin',
                    'domain': None,
                    'createdBy': 'admin',
                    'createdDate': '2025-04-06T10:15:27.424+00:00',
                    'updatedBy': 'admin',
                    'updatedDate': '2025-04-06T10:15:27.425+00:00'
                },
                'references': {
                    'devices': 0,
                    'policies': 0
                }
            },
            '/Api/V1/Credential/d32c5fea-721b-446e-994d-1e0baf921b3a': {
                'credential': {
                    'id': 'd32c5fea-721b-446e-994d-1e0baf921b3a',
                    'label': 'Test Server',
                    'username': 'admin',
                    'domain': None,
                    'createdBy': 'admin',
                    'createdDate': '2025-04-06T10:15:27.424+00:00',
                    'updatedBy': 'admin',
                    'updatedDate': '2025-04-06T10:15:27.425+00:00'
                },
                'references': {
                    'devices': 0,
                    'policies': 0
                }
            }
        })

    def tearDown(self):
        """
        Clean up after each test.
        """
        # Reset version back to 4.0 after each test
        self.DEFAULT_MOCK_RESPONSES[self.RESPONSE_MODE.Valid]['/version'] = '4.0'
        self.MOCK_RESPONSES[self.RESPONSE_MODE.Valid]['/version'] = '4.0'
        super().tearDown()

    def test_server_credential_to_xml(self):
        """
        Test creating XML for a server credential.
        """
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="password123"
        )

        # Convert to XML
        xml_elem = cred.to_xml()

        # Check tag and attributes
        self.assertEqual(xml_elem.tag, "serverCredential")
        self.assertEqual(xml_elem.find("label").text, "Test Server")
        self.assertEqual(xml_elem.find("username").text, "admin")
        self.assertEqual(xml_elem.find("password").text, "password123")
        self.assertIsNone(xml_elem.find("domain"))

    def test_vcenter_credential_with_domain_to_xml(self):
        """
        Test creating XML for a vCenter credential with domain.
        """
        cred = VCenterCredential(
            label="Test vCenter",
            username="vcadmin",
            password="vcpassword",
            domain="vsphere.local"
        )

        # Convert to XML
        xml_elem = cred.to_xml()

        # Check tag and attributes
        self.assertEqual(xml_elem.tag, "vCenterCredential")
        self.assertEqual(xml_elem.find("label").text, "Test vCenter")
        self.assertEqual(xml_elem.find("username").text, "vcadmin")
        self.assertEqual(xml_elem.find("password").text, "vcpassword")
        self.assertEqual(xml_elem.find("domain").text, "vsphere.local")

    def test_create_credential(self):
        """
        Test creating a credential.
        """
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="password123"
        )

        # Mock requests.post to properly handle the XML request
        with mock.patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = self.MOCK_RESPONSES[
                self.RESPONSE_MODE.Valid]['/Api/V1/Credential']

            result = self.client.credential.create(cred)

            # Check result
            self.assertEqual(
                result['credential']['id'],
                'd32c5fea-721b-446e-994d-1e0baf921b3a'
            )
            self.assertEqual(result['credential']['label'], 'Test Server')

            # Verify proper XML was sent
            _, kwargs = mock_post.call_args
            self.assertIn('data', kwargs)
            xml_data = kwargs['data']
            self.assertIn('<serverCredential>', xml_data)
            self.assertIn('<label>Test Server</label>', xml_data)
            self.assertIn('<username>admin</username>', xml_data)
            self.assertIn('<password>password123</password>', xml_data)

    def test_get_credentials(self):
        """
        Test getting all credentials.
        """
        result = self.client.credential.get()

        # Check result
        self.assertEqual(
            result['credential']['id'],
            'd32c5fea-721b-446e-994d-1e0baf921b3a'
        )
        self.assertEqual(result['credential']['label'], 'Test Server')

    def test_get_credential_by_id(self):
        """
        Test getting a credential by ID.
        """
        result = self.client.credential.get(
            entity_id='d32c5fea-721b-446e-994d-1e0baf921b3a'
        )

        # Check result
        self.assertEqual(
            result['credential']['id'],
            'd32c5fea-721b-446e-994d-1e0baf921b3a'
        )
        self.assertEqual(result['credential']['label'], 'Test Server')

    def test_update_credential(self):
        """
        Test updating a credential.
        """
        cred = ServerCredential(
            label="Updated Server",
            username="admin",
            password="newpassword"
        )

        # Mock requests.put to properly handle the XML request
        with mock.patch('requests.put') as mock_put:
            mock_put.return_value.status_code = 200
            mock_put.return_value.json.return_value = {
                'credential': {
                    'id': 'd32c5fea-721b-446e-994d-1e0baf921b3a',
                    'label': 'Updated Server',
                    'username': 'admin',
                    'domain': None,
                    'createdBy': 'admin',
                    'createdDate': '2025-04-06T10:15:27.424+00:00',
                    'updatedBy': 'admin',
                    'updatedDate': '2025-04-06T11:30:27.425+00:00'
                },
                'references': {
                    'devices': 0,
                    'policies': 0
                }
            }

            result = self.client.credential.update(
                'd32c5fea-721b-446e-994d-1e0baf921b3a',
                cred
            )

            # Check result
            self.assertEqual(
                result['credential']['id'],
                'd32c5fea-721b-446e-994d-1e0baf921b3a'
            )
            self.assertEqual(result['credential']['label'], 'Updated Server')

            # Verify proper XML was sent
            _, kwargs = mock_put.call_args
            self.assertIn('data', kwargs)
            xml_data = kwargs['data']
            self.assertIn('<serverCredential>', xml_data)
            self.assertIn('<label>Updated Server</label>', xml_data)
            self.assertIn('<username>admin</username>', xml_data)
            self.assertIn('<password>newpassword</password>', xml_data)

    def test_delete_credential(self):
        """
        Test deleting a credential.
        """
        # Mock requests.delete to properly handle the request
        with mock.patch('requests.delete') as mock_delete:
            mock_delete.return_value.status_code = 200
            mock_delete.return_value.json.return_value = {}

            result = self.client.credential.delete(
                'd32c5fea-721b-446e-994d-1e0baf921b3a'
            )

            # Check result (delete returns empty dict)
            self.assertEqual(result, {})

            # Verify the correct URL was called
            url, _ = mock_delete.call_args
            base_url = 'https://1.2.3.4:443/api/Api/V1/Credential/'
            credential_id = 'd32c5fea-721b-446e-994d-1e0baf921b3a'
            self.assertIn(base_url + credential_id, url)

    def test_version_check(self):
        """
        Test that credential operations check gateway version compatibility.
        """
        # Mock the system.api_version to return 3.5
        with mock.patch.object(self.client.system, 'api_version', return_value='3.5'):
            cred = ServerCredential(
                label="Test Server",
                username="admin",
                password="password123"
            )

            # Check that operations raise version exception
            with self.assertRaises(exceptions.PowerFlexCredentialNotSupported) as context:
                self.client.credential.create(cred)

            # Check for the correct error message
            expected_msg = (
                "Credential operations are not supported for PowerFlex Gateway "
                "version 3.5"
            )
            self.assertIn(expected_msg, str(context.exception))

    def test_invalid_credential_type(self):
        """
        Test that using a credential without a credential_type raises exception.
        """
        cred = BaseCredential(
            label="Test Invalid",
            username="admin",
            password="password"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            cred.to_xml()

        self.assertIn("Credential type not specified", str(context.exception))

    def test_factory_method_server_credential(self):
        """
        Test the factory method for creating a server credential.
        """
        # Create server credential using factory method
        cred = BaseCredential.create_credential(
            credential_type="server",
            label="Factory Server",
            username="admin",
            password="factorypass"
        )

        # Verify it's the correct type
        self.assertIsInstance(cred, ServerCredential)
        self.assertEqual(cred.label, "Factory Server")
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "factorypass")
        self.assertIsNone(cred.domain)
        self.assertEqual(cred.credential_type, "serverCredential")

    def test_factory_method_vcenter_with_domain(self):
        """
        Test the factory method for creating a vCenter credential with domain.
        """
        # Create vCenter credential using factory method
        cred = BaseCredential.create_credential(
            credential_type="vcenter",
            label="Factory vCenter",
            username="vcadmin",
            password="vcpass",
            domain="vsphere.local"
        )

        # Verify it's the correct type and has domain
        self.assertIsInstance(cred, VCenterCredential)
        self.assertEqual(cred.label, "Factory vCenter")
        self.assertEqual(cred.username, "vcadmin")
        self.assertEqual(cred.password, "vcpass")
        self.assertEqual(cred.domain, "vsphere.local")
        self.assertEqual(cred.credential_type, "vCenterCredential")

    def test_factory_method_invalid_type(self):
        """
        Test that factory method raises exception for invalid credential type.
        """
        with self.assertRaises(exceptions.PowerFlexCredentialTypeError) as context:
            BaseCredential.create_credential(
                credential_type="invalid",
                label="Invalid",
                username="user",
                password="pass"
            )

        self.assertIn("Invalid credential type", str(context.exception))

    def test_verify_credential_valid(self):
        """
        Test that verify_credential passes for valid credentials.
        """
        cred = ServerCredential(
            label="Test Verify",
            username="admin",
            password="password123"
        )

        # Verification should return True and not raise any exceptions
        result = self.client.credential.verify_credential(cred)
        self.assertTrue(result)

    def test_verify_credential_missing_label(self):
        """
        Test that verify_credential catches missing label.
        """
        cred = ServerCredential(
            label="",  # Empty label
            username="admin",
            password="password123"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("must have a label", str(context.exception))

    def test_verify_credential_missing_username(self):
        """
        Test that verify_credential catches missing username.
        """
        cred = ServerCredential(
            label="Test Verify",
            username="",  # Empty username
            password="password123"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("must have a username", str(context.exception))

    def test_verify_credential_missing_password(self):
        """
        Test that verify_credential catches missing password.
        """
        cred = ServerCredential(
            label="Test Verify",
            username="admin",
            password=""  # Empty password
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("must have a password", str(context.exception))

    def test_get_credential_type(self):
        """
        Test the get_credential_type method.
        """
        # Create a mock credential response with a server credential type
        credential_data = {
            'serverCredential': {
                'id': '12345',
                'label': 'Server Credential',
                'username': 'admin'
            },
            'references': {
                'devices': 0
            }
        }

        credential_type = self.client.credential.get_credential_type(
            credential_data)
        self.assertEqual(credential_type, "serverCredential")

    def test_get_credential_type_invalid(self):
        """
        Test that get_credential_type raises exception for invalid data.
        """
        # Create a mock response with no valid credential type
        invalid_data = {
            'id': '12345',
            'references': {
                'devices': 0
            }
        }

        with self.assertRaises(exceptions.PowerFlexClientException) as context:
            self.client.credential.get_credential_type(invalid_data)

        self.assertIn("Could not determine credential type",
                      str(context.exception))

    def test_specialized_credential_not_supported_exception(self):
        """
        Test that PowerFlexCredentialNotSupported exception is raised with correct message.
        """
        # Mock the system.api_version to return a version below 4.0
        with mock.patch.object(self.client.system, 'api_version', return_value='3.0'):
            cred = ServerCredential(
                label="Test Server",
                username="admin",
                password="password123"
            )

            with self.assertRaises(exceptions.PowerFlexCredentialNotSupported) as context:
                self.client.credential.create(cred)

            exception_msg = str(context.exception)
            self.assertIn(
                "not supported for PowerFlex Gateway version 3.0",
                exception_msg
            )
            self.assertIn(
                "versions below 4.0 do not support credential management",
                exception_msg
            )

    def test_iom_credential_to_xml(self):
        """
        Test creating XML for an IOM credential.
        """
        cred = IomCredential(
            label="Test IOM",
            username="iomadmin",
            password="iompass123"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "iomCredential")
        self.assertEqual(xml_elem.find("label").text, "Test IOM")
        self.assertEqual(xml_elem.find("username").text, "iomadmin")
        self.assertEqual(xml_elem.find("password").text, "iompass123")
        self.assertIsNone(xml_elem.find("domain"))

    def test_em_credential_with_domain_to_xml(self):
        """
        Test creating XML for an EM credential with domain.
        """
        cred = EmCredential(
            label="Test EM",
            username="emadmin",
            password="empass123",
            domain="em.local"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "emCredential")
        self.assertEqual(xml_elem.find("label").text, "Test EM")
        self.assertEqual(xml_elem.find("username").text, "emadmin")
        self.assertEqual(xml_elem.find("password").text, "empass123")
        self.assertEqual(xml_elem.find("domain").text, "em.local")

    def test_scaleio_credential_to_xml(self):
        """
        Test creating XML for a ScaleIO credential.
        """
        cred = ScaleIOCredential(
            label="Test ScaleIO",
            username="scaleioadmin",
            password="scaleiopass123"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "scaleIoCredential")
        self.assertEqual(xml_elem.find("label").text, "Test ScaleIO")
        self.assertEqual(xml_elem.find("username").text, "scaleioadmin")
        self.assertEqual(xml_elem.find("password").text, "scaleiopass123")
        self.assertIsNone(xml_elem.find("domain"))

    def test_ps_credential_with_domain_to_xml(self):
        """
        Test creating XML for a PS credential with domain.
        """
        cred = PSCredential(
            label="Test PS",
            username="psadmin",
            password="pspass123",
            domain="ps.local"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "psCredential")
        self.assertEqual(xml_elem.find("label").text, "Test PS")
        self.assertEqual(xml_elem.find("username").text, "psadmin")
        self.assertEqual(xml_elem.find("password").text, "pspass123")
        self.assertEqual(xml_elem.find("domain").text, "ps.local")

    def test_os_credential_with_domain_to_xml(self):
        """
        Test creating XML for an OS credential with domain.
        """
        cred = OSCredential(
            label="Test OS",
            username="osadmin",
            password="ospass123",
            domain="os.local"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "osCredential")
        self.assertEqual(xml_elem.find("label").text, "Test OS")
        self.assertEqual(xml_elem.find("username").text, "osadmin")
        self.assertEqual(xml_elem.find("password").text, "ospass123")
        self.assertEqual(xml_elem.find("domain").text, "os.local")

    def test_osuser_credential_with_domain_to_xml(self):
        """
        Test creating XML for an OS User credential with domain.
        """
        cred = OSUserCredential(
            label="Test OS User",
            username="osuseradmin",
            password="osuserpass123",
            domain="osuser.local"
        )

        xml_elem = cred.to_xml()

        self.assertEqual(xml_elem.tag, "osUserCredential")
        self.assertEqual(xml_elem.find("label").text, "Test OS User")
        self.assertEqual(xml_elem.find("username").text, "osuseradmin")
        self.assertEqual(xml_elem.find("password").text, "osuserpass123")
        self.assertEqual(xml_elem.find("domain").text, "osuser.local")

    def test_gateway_version_check_failure(self):
        """
        Test gateway version check failure for unsupported version.
        """
        # Set version to unsupported version
        self.DEFAULT_MOCK_RESPONSES[self.RESPONSE_MODE.Valid]['/version'] = '3.0'
        self.MOCK_RESPONSES[self.RESPONSE_MODE.Valid]['/version'] = '3.0'

        # Reinitialize client with new version
        self.client.initialize()

        # Attempt to create credential should raise exception
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="password123"
        )

        with self.assertRaises(exceptions.PowerFlexCredentialNotSupported):
            self.client.credential.create(cred)

    def test_base_credential_missing_type(self):
        """
        Test that BaseCredential raises error when credential_type is not set.
        """
        cred = BaseCredential(
            label="Test Base",
            username="baseadmin",
            password="basepass123"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            cred.to_xml()

        self.assertIn("Credential type not specified", str(context.exception))

    def test_credential_with_invalid_domain_type(self):
        """
        Test that credential types that don't support domains ignore domain parameter.
        """
        # Create a base credential with domain
        cred = BaseCredential(
            label="Test Server",
            username="admin",
            password="pass123",
            domain="invalid.domain"
        )
        cred.credential_type = "serverCredential"

        xml_elem = cred.to_xml()
        self.assertIsNone(xml_elem.find("domain"))

    def test_create_credential_with_invalid_type(self):
        """
        Test creating credential with invalid type through factory method.
        """
        with self.assertRaises(exceptions.PowerFlexCredentialTypeError) as context:
            BaseCredential.create_credential(
                credential_type="invalid_type",
                label="Test Invalid",
                username="invalid",
                password="invalid"
            )

        self.assertIn("Invalid credential type", str(context.exception))

    def test_credential_validation_missing_fields(self):
        """
        Test credential validation with missing required fields.
        """
        # Test missing label
        cred = ServerCredential(
            label="",  # Empty label
            username="admin",
            password="pass123"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("must have a label", str(context.exception))

    def test_credential_update_with_invalid_id(self):
        """
        Test updating credential with invalid ID.
        """
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="pass123"
        )

        # Mock requests.put to return a 404 error
        with mock.patch('requests.put') as mock_put:
            mock_put.return_value.status_code = 404
            mock_put.return_value.json.return_value = {
                'error': 'Credential not found'
            }

            with self.assertRaises(exceptions.PowerFlexFailCredentialOperation) as context:
                self.client.credential.update("invalid-id", cred)

            self.assertIn("Credential not found", str(context.exception))

    def test_credential_validation_malformed_xml(self):
        """
        Test credential validation with malformed XML data.
        """
        # Create a credential with invalid characters that would break XML
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="pass<123>"  # Invalid XML characters
        )

        # The XML validation should pass since the XML library handles escaping
        result = self.client.credential.verify_credential(cred)
        self.assertTrue(result)

    def test_validate_credential_type_direct(self):
        """
        Test the _validate_credential_type method directly.
        """
        # Test with missing credential_type
        cred = ServerCredential(
            label="Test Server",
            username="admin",
            password="pass123"
        )
        cred.credential_type = None

        with self.assertRaises(exceptions.PowerFlexCredentialTypeError):
            self.client.credential._validate_credential_type(cred)

        # Test with invalid credential_type
        cred.credential_type = "invalidType"
        with self.assertRaises(exceptions.PowerFlexCredentialTypeError) as context:
            self.client.credential._validate_credential_type(cred)

        self.assertIn("invalidType", str(context.exception))

    def test_domain_support_edge_cases(self):
        """
        Test edge cases for domain support in credentials.
        """
        # Test domain with empty string
        cred = VCenterCredential(
            label="Test vCenter",
            username="admin",
            password="pass123",
            domain=""  # Empty domain
        )

        xml_elem = cred.to_xml()
        domain_elem = xml_elem.find("domain")
        self.assertIsNotNone(domain_elem)
        self.assertEqual(domain_elem.text, "")

        # Test domain with whitespace
        cred = VCenterCredential(
            label="Test vCenter",
            username="admin",
            password="pass123",
            domain="   "  # Whitespace domain
        )

        xml_elem = cred.to_xml()
        domain_elem = xml_elem.find("domain")
        self.assertIsNotNone(domain_elem)
        self.assertEqual(domain_elem.text, "   ")

        # Test domain with special characters
        cred = VCenterCredential(
            label="Test vCenter",
            username="admin",
            password="pass123",
            domain="domain@test.com"  # Special characters
        )

        xml_elem = cred.to_xml()
        domain_elem = xml_elem.find("domain")
        self.assertIsNotNone(domain_elem)
        self.assertEqual(domain_elem.text, "domain@test.com")

    def test_credential_validation_with_malformed_data(self):
        """
        Test credential validation with various malformed data scenarios.
        """
        # Test with None values
        cred = ServerCredential(
            label=None,
            username="admin",
            password="pass123"
        )

        with self.assertRaises(exceptions.InvalidInput) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("must have a label", str(context.exception))

        # Test with non-string values
        cred = ServerCredential(
            label=123,  # Non-string label
            username="admin",
            password="pass123"
        )

        with self.assertRaises(exceptions.PowerFlexClientException) as context:
            self.client.credential.verify_credential(cred)

        self.assertIn("cannot serialize", str(context.exception))

        # Test with extremely long values
        cred = ServerCredential(
            label="a" * 1000,  # Very long label
            username="admin",
            password="pass123"
        )

        # Long values should be accepted
        result = self.client.credential.verify_credential(cred)
        self.assertTrue(result)

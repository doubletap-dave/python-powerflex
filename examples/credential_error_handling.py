#!/usr/bin/env python
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

"""
Example demonstrating error handling for credential management operations.
"""

import sys
import logging
from PyPowerFlex import PowerFlexClient
from PyPowerFlex import exceptions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function demonstrating error handling for credential operations."""
    # Connection parameters
    server_ip = "192.168.1.100"  # Replace with your PowerFlex Manager IP
    username = "admin"            # Replace with your username
    password = "password"         # Replace with your password
    verify_ssl = False           # Set to True in production
    
    try:
        # Initialize the client
        client = PowerFlexClient(
            server_ip=server_ip,
            username=username,
            password=password,
            verify_ssl=verify_ssl
        )
        
        # Example 1: Invalid credential type
        try:
            logger.info("Attempting to add credential with invalid type:")
            client.credential.add_credential(
                credential_type="InvalidType",
                username="user",
                password="password"
            )
        except exceptions.PowerFlexInvalidCredentialType as e:
            logger.error(f"Expected error: {e}")
        
        # Example 2: Credential not found
        try:
            logger.info("Attempting to get non-existent credential:")
            client.credential.get_credential_details("non_existent_id")
        except exceptions.PowerFlexCredentialNotFound as e:
            logger.error(f"Expected error: {e}")
        
        # Example 3: Update non-existent credential
        try:
            logger.info("Attempting to update non-existent credential:")
            client.credential.update_credential(
                "non_existent_id",
                username="new_user",
                password="new_password"
            )
        except exceptions.PowerFlexCredentialNotFound as e:
            logger.error(f"Expected error: {e}")
        
        # Example 4: Delete non-existent credential
        try:
            logger.info("Attempting to delete non-existent credential:")
            client.credential.delete_credential("non_existent_id")
        except exceptions.PowerFlexCredentialNotFound as e:
            logger.error(f"Expected error: {e}")
        
        # Example 5: Field length validation
        try:
            logger.info("Attempting to add credential with too long username:")
            # Create a username that exceeds the maximum length
            long_username = "a" * 129  # Assuming max length is 128
            client.credential.add_credential(
                credential_type="Host",
                username=long_username,
                password="password"
            )
        except exceptions.PowerFlexClientException as e:
            logger.error(f"Expected error: {e}")
        
        # Example 6: Gateway connection (if applicable)
        # This would require connecting to a Gateway instead of a Manager
        # try:
        #     gateway_client = PowerFlexClient(
        #         server_ip="gateway_ip",
        #         username="admin",
        #         password="password",
        #         verify_ssl=False
        #     )
        #     gateway_client.credential.list_credentials()
        # except exceptions.PowerFlexFailCredentialOperation as e:
        #     logger.error(f"Expected error: {e}")
        
    except exceptions.PowerFlexClientException as e:
        logger.error(f"PowerFlex error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
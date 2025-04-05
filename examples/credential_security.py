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
Example demonstrating security best practices for credential management.
"""

import sys
import os
import logging
import getpass
from PyPowerFlex import PowerFlexClient
from PyPowerFlex import exceptions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_secure_input(prompt, is_password=False):
    """
    Get secure input from the user.
    
    :param prompt: The prompt to display
    :param is_password: Whether the input is a password
    :return: The user input
    """
    if is_password:
        return getpass.getpass(prompt)
    return input(prompt)

def load_credentials_from_env():
    """
    Load credentials from environment variables.
    
    :return: Tuple of (server_ip, username, password)
    """
    server_ip = os.environ.get('POWERFLEX_SERVER_IP')
    username = os.environ.get('POWERFLEX_USERNAME')
    password = os.environ.get('POWERFLEX_PASSWORD')
    
    return server_ip, username, password

def main():
    """Main function demonstrating security best practices for credential operations."""
    # Try to load credentials from environment variables first
    server_ip, username, password = load_credentials_from_env()
    
    # If not found in environment, prompt the user
    if not server_ip:
        server_ip = get_secure_input("Enter PowerFlex Manager IP: ")
    if not username:
        username = get_secure_input("Enter username: ")
    if not password:
        password = get_secure_input("Enter password: ", is_password=True)
    
    # Always use SSL verification in production
    verify_ssl = True
    
    try:
        # Initialize the client with secure settings
        client = PowerFlexClient(
            server_ip=server_ip,
            username=username,
            password=password,
            verify_ssl=verify_ssl
        )
        
        # Example 1: Secure credential creation with strong password
        logger.info("Creating a credential with a strong password:")
        # In a real scenario, you would generate a strong password
        strong_password = "ComplexP@ssw0rd123!@#$%^&*()"
        
        # Create a credential with minimal required information
        new_credential = client.credential.add_credential(
            credential_type="Host",
            username="secure_user",
            password=strong_password
        )
        credential_id = new_credential.get('id')
        logger.info(f"Created credential with ID: {credential_id}")
        
        # Example 2: Secure credential update
        logger.info("Updating credential with a new strong password:")
        # In a real scenario, you would generate a new strong password
        new_strong_password = "NewComplexP@ssw0rd456!@#$%^&*()"
        
        # Update only the password, preserving other settings
        updated = client.credential.update_credential(
            credential_id,
            password=new_strong_password
        )
        logger.info("Credential updated successfully")
        
        # Example 3: Secure credential retrieval
        logger.info("Retrieving credential details:")
        details = client.credential.get_credential_details(credential_id)
        
        # Only log non-sensitive information
        logger.info(f"Credential type: {details.get('credentialType')}")
        logger.info(f"Username: {details.get('username')}")
        # Never log the password
        
        # Example 4: Secure credential deletion
        logger.info("Deleting credential:")
        client.credential.delete_credential(credential_id)
        logger.info("Credential deleted successfully")
        
        # Example 5: Listing credentials with filtering
        logger.info("Listing credentials of a specific type:")
        # Only retrieve credentials of a specific type
        host_credentials = client.credential.list_credentials(
            filter_fields={"credentialType": "Host"}
        )
        
        # Only log non-sensitive information
        for cred in host_credentials:
            logger.info(f"Credential ID: {cred.get('id')}, Type: {cred.get('credentialType')}")
        
    except exceptions.PowerFlexClientException as e:
        logger.error(f"PowerFlex error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
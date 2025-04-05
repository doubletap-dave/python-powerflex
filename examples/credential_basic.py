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
Basic example demonstrating credential management operations.
"""

import sys
import logging
from PyPowerFlex import PowerFlexClient
from PyPowerFlex import exceptions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function demonstrating credential operations."""
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
        
        # List all credentials
        logger.info("Listing all credentials:")
        credentials = client.credential.list_credentials()
        for cred in credentials:
            logger.info(f"Credential ID: {cred.get('id')}, Type: {cred.get('credentialType')}")
        
        # Add a new host credential
        logger.info("Adding a new host credential:")
        new_credential = client.credential.add_credential(
            credential_type="Host",
            username="host_user",
            password="host_password"
        )
        logger.info(f"Added credential with ID: {new_credential.get('id')}")
        
        # Get credential details
        credential_id = new_credential.get('id')
        logger.info(f"Getting details for credential ID: {credential_id}")
        details = client.credential.get_credential_details(credential_id)
        logger.info(f"Credential details: {details}")
        
        # Update the credential
        logger.info(f"Updating credential ID: {credential_id}")
        updated = client.credential.update_credential(
            credential_id,
            username="updated_host_user",
            password="updated_host_password"
        )
        logger.info(f"Updated credential: {updated}")
        
        # Delete the credential
        logger.info(f"Deleting credential ID: {credential_id}")
        client.credential.delete_credential(credential_id)
        logger.info("Credential deleted successfully")
        
    except exceptions.PowerFlexClientException as e:
        logger.error(f"PowerFlex error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
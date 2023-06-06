# Network Security Monitoring

This script retrieves information from the Sophos API to see if any agents have tamper protection turned off. If detected an IT admin is notified based on the emails defined in the config.ini file. 
The script will also connect to the Meraki API and disable the switchport that has the client connected to it.  

## Features

- Fetches data from the Sophos API to retrieve network device information.
- Authenticates using the Sophos API.
- Retrieves data from the Meraki API to retrieve client information.
- Filters clients based on MAC addresses from Sophos.
- Performs switchport shutdown using the Meraki API for specific detections.
- Sends email notifications with relevant detection information.

## Prerequisites

- Python 3.6 or higher
- Required Python libraries: requests, smtplib

# Network Security Monitoring

## Configuration

Make sure to configure the `config.ini` file with the following details:

### [Email]

- `sender_email`: The email address of the sender.
- `receiver_email`: The email address of the receiver.
- `subject`: The subject of the email.
- `sender_password`: The password of the sender's email account.

### [Sophos]

- `auth_url`: The URL for Sophos authentication.
- `grant_type`: The grant type for Sophos authentication.
- `scope`: The scope for Sophos authentication.
- `client_id`: The client ID for Sophos authentication.
- `client_secret`: The client secret for Sophos authentication.
- `url`: The URL for the Sophos API endpoint.
- `pageSize`: The page size for the Sophos API.
- `tamperProtectionEnabled`: The tamper protection status for the Sophos API.

### [Meraki]

- `meraki_api_key`: The API key for the Meraki API.
- `meraki_network_id`: The ID of the Meraki network.

**Disclaimer**
Please note that this script is provided as-is and is intended for educational purposes only. Use it at your own risk. The authors and contributors of this script are not responsible for any misuse or damages caused by the script.


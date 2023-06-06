import requests
import smtplib
from email.mime.text import MIMEText
from configparser import ConfigParser

# Read configuration from config.ini file
config = ConfigParser()
config.read('config.ini')

# Email details
sender_email = config.get('Email', 'sender_email')
receiver_email = config.get('Email', 'receiver_email')
subject = config.get('Email', 'subject')
sender_password = config.get('Email', 'sender_password')

# Sophos Authentication details
auth_url = config.get('Sophos', 'auth_url')
auth_data = {
    'grant_type': config.get('Sophos', 'grant_type'),
    'scope': config.get('Sophos', 'scope'),
    'client_id': config.get('Sophos', 'client_id'),
    'client_secret': config.get('Sophos', 'client_secret')
}

# Sophos Endpoint details
url = config.get('Sophos', 'url')
params = {
    'pageSize': config.get('Sophos', 'pageSize'),
    'tamperProtectionEnabled': config.get('Sophos', 'tamperProtectionEnabled')
}

# Meraki API details
meraki_api_key = config.get('Meraki', 'meraki_api_key')
meraki_network_id = config.get('Meraki', 'meraki_network_id')


def send_email(detections):
    # Create the message body
    message_parts = []
    for detection in detections:
        hostname = detection['hostname']
        ipv4Addresses = detection['ipv4Addresses']
        macAddresses = detection['macAddresses']
        viaLogin = detection['associatedPerson']['viaLogin']
        switchport = detection.get('switchport', None)  # Get the switchport if available
        recentDeviceSerial = detection.get('recentDeviceSerial', None)  # Get the recentDeviceSerial if available

        message_parts.append(f'Hostname: {hostname}\nIPv4 Addresses: {ipv4Addresses}\nMAC Addresses: {macAddresses}\nVia Login: {viaLogin}\n')
        if switchport:
            message_parts.append(f'Switchport (Shutdown): {switchport}\n')
        if recentDeviceSerial:
            message_parts.append(f'Switch: {recentDeviceSerial}\n')
        message_parts.append('---\n')

    # Create email message
    msg = MIMEText(''.join(message_parts))
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    # Send email
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)


# Perform Sophos authentication
auth_response = requests.post(auth_url, data=auth_data)

# Check the authentication response
if auth_response.status_code == 200:
    auth_data = auth_response.json()
    access_token = auth_data['access_token']

    # Fetch the Sophos "id" from whoami endpoint
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    whoami_headers = {
        'Authorization': f'Bearer {access_token}'
    }
    whoami_response = requests.get(whoami_url, headers=whoami_headers)

    # Check the whoami response status code
    if whoami_response.status_code == 200:
        whoami_data = whoami_response.json()
        sophos_id = whoami_data['id']

        headers = {
            'X-Tenant-ID': sophos_id,
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        # Retrieve data from Sophos endpoint
        with requests.Session() as session:
            response = session.get(url, params=params, headers=headers)

        # Check the response status code
        if response.status_code == 200:
            data = response.json()
            items = data['items']

            sophos_mac_addresses = set()  # Store Sophos MAC addresses for filtering
            detections = []  # List to store the detections

            for item in items:
                hostname = item['hostname']
                ipv4Addresses = item['ipv4Addresses']
                macAddresses = {mac.lower() for mac in item['macAddresses']}
                viaLogin = item['associatedPerson']['viaLogin']

                # Append Sophos MAC addresses to the set
                sophos_mac_addresses.update(macAddresses)

                detection = {
                    'hostname': hostname,
                    'ipv4Addresses': ipv4Addresses,
                    'macAddresses': macAddresses,
                    'associatedPerson': {
                        'viaLogin': viaLogin
                    }
                }

                detections.append(detection)

            # Retrieve clients data from Meraki
            meraki_url = f'https://api.meraki.com/api/v1/networks/{meraki_network_id}/clients'
            meraki_headers = {
                'X-Cisco-Meraki-API-Key': meraki_api_key,
                'Content-Type': 'application/json'
            }

            with requests.Session() as session:
                meraki_response = session.get(meraki_url, headers=meraki_headers)

            # Check the response status code
            if meraki_response.status_code == 200:
                meraki_data = meraki_response.json()
                meraki_clients = {client['mac'].lower(): client for client in meraki_data}

                for detection in detections:
                    macAddresses = detection['macAddresses']

                    for mac in macAddresses:
                        if mac in meraki_clients:
                            client = meraki_clients[mac]
                            detection['switchport'] = client.get('switchport', None)
                            detection['recentDeviceSerial'] = client.get('recentDeviceSerial', None)

                            # Switchport shutdown using Meraki API
                            if detection['switchport']:
                                switch_serial = detection['recentDeviceSerial']
                                port_number = detection['switchport']
                                switchport_url = f"https://api.meraki.com/api/v1/devices/{switch_serial}/switch/ports/{port_number}"
                                switchport_payload = {
                                    'enabled': False
                                }
                                switchport_headers = {
                                    'X-Cisco-Meraki-API-Key': meraki_api_key,
                                    'Content-Type': 'application/json'
                                }

                                with requests.Session() as session:
                                    switchport_response = session.put(switchport_url, json=switchport_payload,
                                                                       headers=switchport_headers)

                                if switchport_response.status_code != 200:
                                    print('Switchport shutdown failed for switch', switch_serial, 'and port',
                                          port_number)
                            break
                    else:
                        detection['switchport'] = None
                        detection['recentDeviceSerial'] = None

            # Send email for all detections
            if detections:
                send_email(detections)
        else:
            print('Endpoint request failed with status code:', response.status_code)
    else:
        print('Whoami request failed with status code:', whoami_response.status_code)
else:
    print('Authentication request failed with status code:', auth_response.status_code)

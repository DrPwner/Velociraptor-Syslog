#!/usr/bin/env python3
"""
Velociraptor Syslog Monitor and Email Notification System

This script listens for Velociraptor syslog messages on UDP port 514,
parses them to identify specific actions, and sends email notifications
with relevant details.
"""

import re
import socket
import smtplib
import logging
import argparse
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import threading
import queue
import time
import codecs
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("velociraptor_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('velociraptor_monitor')

# Regular Expression Patterns
PATTERNS = {

    'command_execution': re.compile(
        r'details="(?P<raw_details>\{.*?Windows\.System\.(?:Cmd|Power)Shell.*?\})".*?principal=(?P<principal>\w+)',
        re.DOTALL
    ),
    'quarantine_host': re.compile(
        r'msg=ScheduleFlow.*?Windows\.Remediation\.Quarantine'
        r'(?!.*RemovePolicy)'
        r'.*?principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),
    'quarantine_removed': re.compile(
       r'artifact\\":\\"Windows\.Remediation\.Quarantine.*?key\\":\\"RemovePolicy\\",\\"value\\":\\"Y\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'label_added': re.compile(
       r'msg=SetClientLabel.*?label\\":\\"(?!Quarantine)(?P<label>[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),

    'directory_traversal': re.compile(
        r'details=".*?\{\\"key\\":\\"Path\\",\\"value\\":\\"(?P<path>[^\\"]+)\\".*?'
        r'\\"key\\":\\"Depth\\",\\"value\\":\\"0\\".*?principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),
    'recursive_directory': re.compile(
        r'details="\{\\"client\\":\\"(?P<client_id>C\.[^\\"]+)\\".*?'
        r'System\.VFS\.ListDirectory.*?\{\\"key\\":\\"Path\\",\\"value\\":\\"(?P<path>[^\\"]+)\\".*?'
        r'\\"key\\":\\"Depth\\",\\"value\\":\\"(?P<depth>[1-9][0-9]*)\\".*?principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),
    'run_hunt': re.compile(
        r'msg=ModifyHunt\s+details="\{\\"hunt_id\\":\\"(?P<hunt_id>H\.[^\\"]+)\\",.*?\\"state\\":2\}.*?principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),
    'hunt_canceled': re.compile(
       r'Server\.Utils\.CancelHunt.*?\{\\"key\\":\\"HuntId\\",\\"value\\":\\"(?P<hunt_id>H\.[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'hunt_deletion': re.compile(
       r'msg=ScheduleFlow.*?artifact\\":\\"Server\.Hunts\.CancelAndDelete.*?key\\":\\"HuntId\\",\\"value\\":\\"(?P<hunt_id>H\.[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'hunt_delete': re.compile(
       r'msg=hunt_delete.*?hunt_id\\":\\"(?P<hunt_id>H\.[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'recursive_download': re.compile(
       r'System\.VFS\.DownloadFile.*?key\\":\\"Recursively\\",\\"value\\":\\"Y\\"',
       re.IGNORECASE
    ),

    'label_removed': re.compile(
       r'msg=RemoveClientLabel.*?label\\":\\"(?!Quarantine)(?P<label>[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'directory_traversal_ntfs': re.compile(
       r'artifact\\":\\"System\.VFS\.ListDirectory.*?key\\":\\"Accessor\\",\\"value\\":\\"ntfs\\".*?key\\":\\"Depth\\",\\"value\\":\\"0\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),
    'recursive_directory_ntfs': re.compile(
        r'artifact\\":\\"System\.VFS\.ListDirectory.*?key\\":\\"Accessor\\",\\"value\\":\\"ntfs\\".*?key\\":\\"Depth\\",\\"value\\":\\"(?P<depth>[1-9][0-9]*)\\".*?principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),


    'recursive_download_ntfs': re.compile(
       r'artifact\\":\\"System\.VFS\.DownloadFile.*?key\\":\\"Recursively\\",\\"value\\":\\"Y\\".*?key\\":\\"Accessor\\",\\"value\\":\\"ntfs\\".*?client\\":\\"(?P<client_id>C\.[^\\"]+)\\".*?principal=(?P<principal>\w+)',
       re.IGNORECASE
    ),

    'set_artifact': re.compile(
        r'msg=SetArtifactFile details="\{(?=.*description:)(?P<details>.*?)\}" operation=SetArtifactFile principal=(?P<principal>\w+)',
        re.IGNORECASE | re.DOTALL
    ),
    'delete_artifact': re.compile(
        r'msg=SetArtifactFile details="\{(?=.*name:)(?!.*description:)(?P<details>.*?)\}" operation=SetArtifactFile principal=(?P<principal>\w+)',
        re.IGNORECASE | re.DOTALL
    ),
    'user_create': re.compile(
        r'msg=user_create details="\{.*?\\"username\\":\\"(?P<username>\w+)\\".*?org_ids\\":\[\\"root\\"]\}?" operation=user_create principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),

    'org_create': re.compile(
        r'msg=org_create details="\{(?P<details>.*?)\}" operation=org_create principal=(?P<principal>\w+)',
        re.IGNORECASE
    ),


    'hunt_created': re.compile(r'msg=CreateHunt details="{(?P<details>.*?)}" operation=CreateHunt principal=(?P<principal>\w+)'),
    'password_reset': re.compile(r'msg="Update password" details="{(?P<details>.*?)}" operation="Update password" principal=(?P<principal>\w+)'),
    'registry_traversal': re.compile(r'msg=ScheduleFlow.*?System\.VFS\.ListDirectory.*?Accessor","value":"registry".*?principal=(?P<principal>\w+)'),

#    'user_grant': re.compile(r'msg=user_grant details="{(?P<details>.*?)}" operation=user_grant principal=(?P<principal>\w+)'),
#    'user_logon': re.compile(r'method=GET remote="(?P<remote>.*?)" status=\d+ url=/app/index\.html user=(?P<user>\w+) user-agent="(?P<user_agent>.*?)"')
}

class EmailConfig:
    """Email configuration container"""
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password, recipient_emails, cc_emails=None, use_tls=True):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_emails = [email.strip() for email in recipient_emails.split(',')]
        self.cc_emails = [email.strip() for email in cc_emails.split(',')] if cc_emails else []
        self.use_tls = use_tls



class SyslogUDPHandler:
    """Handler for syslog UDP messages"""
    def __init__(self, host='0.0.0.0', port=514, message_queue=None):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.message_queue = message_queue
        self.running = False

    def start(self):
        """Start the UDP listener"""
        try:
            self.sock.bind((self.host, self.port))
            self.running = True
            logger.info(f"Started UDP listener on {self.host}:{self.port}")

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(8192)
                    msg = data.decode('utf-8')
                    logger.debug(f"Received message from {addr}: {msg}")

                    if self.message_queue:
                        self.message_queue.put(msg)
                except socket.error as e:
                    logger.error(f"Socket error: {e}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        except Exception as e:
            logger.error(f"Error starting UDP listener: {e}")
        finally:
            self.sock.close()

    def stop(self):
        """Stop the UDP listener"""
        self.running = False
        self.sock.close()
        logger.info("Stopped UDP listener")

class MessageProcessor:
    """Process syslog messages and send emails"""
    def __init__(self, message_queue, email_config):
        self.message_queue = message_queue
        self.email_config = email_config
        self.running = False

    def start(self):
        """Start processing messages"""
        self.running = True
        logger.info("Started message processor")

        while self.running:
            try:
                if not self.message_queue.empty():
                    msg = self.message_queue.get()
                    self.process_message(msg)
                    self.message_queue.task_done()
                else:
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error processing message queue: {e}")

    def stop(self):
        """Stop processing messages"""
        self.running = False
        logger.info("Stopped message processor")

    def process_message(self, message):
        """Process a syslog message"""
        try:
            # Print first part of the message for debugging
            logger.debug(f"Processing message: {message[:150]}...")

            for msg_type, pattern in PATTERNS.items():
                match = pattern.search(message)
                if match:
                    logger.info(f"Detected {msg_type} message")

                    # Skip sending hunt_delete if hunt_deletion will follow
                    if msg_type == "hunt_delete" and "Server.Hunts.CancelAndDelete" in message:
                        logger.debug("Skipping hunt_delete alert because hunt_deletion will follow.")
                        return
                    # Extract details from message
                    details_match = re.search(r'details="({.*?})"', message)
                    details = details_match.group(1) if details_match else "{}"

                    email_content = self.generate_email_content(msg_type, match, message, details)
                    if email_content:
                        self.send_email(f"Velociraptor {msg_type.replace('_', ' ').title()} Alert", email_content)
                    break
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def extract_client_id(self, message, details=None):
        """Extract client ID from details JSON or message"""
        try:
            # Try to get client ID from details first
            if details:
                try:
                    details_dict = json.loads(details.replace('\\"', '"'))
                    if 'client_id' in details_dict:
                        return details_dict['client_id']
                    elif 'client' in details_dict:
                        return details_dict['client']
                    elif 'details' in details_dict and 'client_id' in details_dict['details']:
                        return details_dict['details']['client_id']
                except:
                    pass

            # If that fails, try to extract from the full message
            client_match = re.search(r'\"client(?:_id)?\":\"(C\.[a-f0-9]+)\"', message)
            if client_match:
                return client_match.group(1)

            return None
        except Exception as e:
            logger.error(f"Error extracting client ID: {e}")
            return None

    def extract_client_id_ntfs(self, message):
        """Extract client ID specifically from NTFS-style logs"""
        try:
            match = re.search(r'\\"client\\":\\"(C\.[a-f0-9]+)\\"', message)
            if match:
                return match.group(1)
            return None
        except Exception as e:
            logger.error(f"Error extracting NTFS client ID: {e}")
            return None





    def extract_hunt_info(self, message, details=None):
        """Extract hunt information from details JSON or message"""
        try:
            hunt_id = None
            title = None
            description = None
            artifacts = None

            # Try to extract from details
            if details:
                try:
                    details_dict = json.loads(details.replace('\\"', '"'))

                    if 'hunt_id' in details_dict:
                        hunt_id = details_dict['hunt_id']

                    if 'details' in details_dict:
                        if 'hunt_id' in details_dict['details']:
                            hunt_id = details_dict['details']['hunt_id']

                        if 'tags' in details_dict['details']:
                            title = ', '.join(details_dict['details']['tags'])

                        if 'hunt_description' in details_dict['details']:
                            description = details_dict['details']['hunt_description']

                        if 'start_request' in details_dict['details'] and 'artifacts' in details_dict['details']['start_request']:
                            artifacts = ', '.join(details_dict['details']['start_request']['artifacts'])
                except:
                    pass

            # If failed to extract all info, try from the full message
            if not hunt_id:
                hunt_match = re.search(r'\"hunt_id\":\"(H\.\w+)\"', message)
                if hunt_match:
                    hunt_id = hunt_match.group(1)

            if not title:
                title_match = re.search(r'\"tags\":\[\"(.*?)\"\]', message)
                if title_match:
                    title = title_match.group(1)

            if not description:
                desc_match = re.search(r'\"hunt_description\":\"(.*?)\"', message)
                if desc_match:
                    description = desc_match.group(1)

            if not artifacts:
                artifacts_match = re.search(r'\"artifacts\":\[\"(.*?)\"\]', message)
                if artifacts_match:
                    artifacts = artifacts_match.group(1)

            return hunt_id, title, description, artifacts
        except Exception as e:
            logger.error(f"Error extracting hunt info: {e}")
            return None, None, None, None

    def extract_user_info(self, message, details=None):
        """Extract user information from details JSON or message"""
        try:
            username = None
            roles = []

            # Try to extract from details
            if details:
                try:
                    details_dict = json.loads(details.replace('\\"', '"'))

                    if 'username' in details_dict:
                        username = details_dict['username']

                    if 'acl' in details_dict and 'roles' in details_dict['acl']:
                        roles = details_dict['acl']['roles']
                except:
                    pass

            # If failed to extract, try from the full message
            if not username:
                username_match = re.search(r'\"username\":\"(\w+)\"', message)
                if username_match:
                    username = username_match.group(1)

            if not roles:
                roles_match = re.search(r'\"roles\":\[(.*?)\]', message)
                if roles_match:
                    roles_str = roles_match.group(1)
                    roles = [r.strip('"') for r in roles_str.split(',')]

            return username, roles
        except Exception as e:
            logger.error(f"Error extracting user info: {e}")
            return None, None

    def extract_path_from_message(self, message):
        """Extract file path from message"""
        try:
            # Look for path value in message
            path_match = re.search(r'Path\",\"value\":\"(.*?)\"', message)
            if path_match:
                return path_match.group(1)

            # Try to extract components from message
            components_match = re.search(r'Components\",\"value\":\"(\[.*?\])\"', message)
            if components_match:
                components_raw = components_match.group(1)
                logger.debug(f"Raw components string: {components_raw}")
                try:
                    components = json.loads(components_raw)
                    if components:
                        return '\\'.join(components)
                except Exception as parse_error:
                    logger.error(f"Failed to parse components: {components_raw} | Error: {parse_error}")
                    pass

            return None
        except Exception as e:
            logger.error(f"Error extracting path: {e}")
            return None



    def extract_artifact_name(self, message, details=None):
        """Extract artifact name from details or message"""
        try:
            # First try to find 'name:' followed by the first word only (excluding \n and extra YAML keys)
            name_match = re.search(r'name:\s*([^\s\\]+)', message)
            if name_match:
                return name_match.group(1)

            # Fallback to artifact key if available
            artifact_match = re.search(r'\\"artifact\\":\\"([^\\"]+)\\"', message)
            if artifact_match:
                return artifact_match.group(1)

            return None
        except Exception as e:
            logger.error(f"Error extracting artifact name: {e}")
            return None


    def _extract_principal(self, message):
        match = re.search(r'principal=(\w+)', message)
        return match.group(1) if match else "unknown"

    def generate_email_content(self, msg_type, match, full_message, details=None):
        """Generate email content based on message type"""
        timestamp = self._extract_timestamp(full_message)
        principal = match.group('principal') if 'principal' in match.groupdict() else "unknown"


        if msg_type == 'hunt_canceled':
            hunt_id = match.group('hunt_id')
            return f"User {principal} canceled hunt \"{hunt_id}\" on {timestamp}."

        elif msg_type == 'command_execution':
            try:
                principal = match.group('principal')
                raw_details = match.group('raw_details')


                unescaped = codecs.decode(raw_details, 'unicode_escape')
                details_dict = json.loads(unescaped)

                client_id = details_dict.get('client') or details_dict.get('details', {}).get('client_id')
                artifact = details_dict.get('details', {}).get('artifacts', [None])[0]

                env = (
                    details_dict.get('details', {})
                    .get('specs', [{}])[0]
                    .get('parameters', {})
                    .get('env', [])
                )

                command = next((e.get("value") for e in env if e.get("key") == "Command"), None)

                if not command or not artifact:
                    return None

                if artifact == "Windows.System.PowerShell":
                    return f"User {principal} executed \"{command}\" command through \"Powershell\" on endpoint \"{client_id}\" on {timestamp}"
                elif artifact == "Windows.System.CmdShell":
                    return f"User {principal} executed \"{command}\" command through \"CMD Shell\" on endpoint \"{client_id}\" on {timestamp}"
            except Exception as e:
                logger.error(f"Failed to parse ScheduleFlow command: {e}")
                return None






        elif msg_type == 'hunt_created':
            hunt_id, title, description, artifacts = self.extract_hunt_info(full_message, details)
            orgs = self._extract_orgs(full_message, details)
            return f"User {principal} Created a hunt \"{artifacts}\" ({hunt_id}), with a title of \"{title}\" and a description of \"{description}\" on \"{orgs}\" org on {timestamp}."

        elif msg_type == 'hunt_delete':
            hunt_id = match.group('hunt_id')
            return f"User {principal} completed deletion of hunt {hunt_id} on {timestamp}."

        elif msg_type == 'delete_artifact':
            artifact_name = self.extract_artifact_name(full_message, details)
            return f"User {principal} deleted the artifact titled \"{artifact_name}\" on {timestamp}."

        elif msg_type == 'org_create':
            try:
                details_dict = json.loads(details.replace('\\"', '"'))
                org_name = details_dict.get('name', 'unknown')
                org_id = details_dict.get('org_id', 'unknown')
                return f"User {principal} created a new organization named \"{org_name}\" with ID \"{org_id}\" on {timestamp}."
            except Exception as e:
                logger.error(f"Error parsing org_create details: {e}")
                return f"User {principal} created a new organization on {timestamp}."



        elif msg_type == 'run_hunt':
            hunt_id, _, _, _ = self.extract_hunt_info(full_message, details)
            return f"User {principal} executed hunt {hunt_id} on {timestamp}."

        elif msg_type == 'quarantine_host':
            client_id = self.extract_client_id(full_message, details)
            return f"User {principal} Quarantined the following endpoint(s): {client_id} on {timestamp}."

        elif msg_type == 'label_added':
            client_id = self.extract_client_id(full_message, details)
            label = match.group('label') if 'label' in match.groupdict() else "unknown"
            return f"User {principal} Added a Lable to endpoint \"{client_id}\": \"{label}\" on {timestamp}."

        elif msg_type == 'label_removed':
            client_id = self.extract_client_id(full_message, details)
            label = match.group('label') if 'label' in match.groupdict() else "unknown"
            return f"User {principal} Removed Label \"{label}\" from {client_id} on {timestamp}."

        elif msg_type == 'password_reset':
            try:
                details_dict = json.loads(details.replace('\\"', '"'))
                target_user = details_dict.get('user', 'unknown')
                operation_type = details_dict.get('operation', '').lower()

                if target_user.lower() == principal.lower():
                    return f"User {principal} updated their own password on {timestamp}."
                else:
                    return f"User {principal} reset the password of user \"{target_user}\" on {timestamp}."
            except Exception as e:
                logger.error(f"Error parsing password reset details: {e}")
                return f"User {principal} performed a password update on {timestamp}."


        elif msg_type == 'quarantine_removed':
            client_id = self.extract_client_id(full_message, details)
            return f"User {principal} Removed Isolation on endpoint {client_id} on {timestamp}."

        elif msg_type == 'directory_traversal':
            client_id = self.extract_client_id(full_message, details)
            path = match.group('path') if 'path' in match.groupdict() and match.group('path') else None

            if not path:
                path = self.extract_path_from_message(full_message)

            if not path:
                return f"User {principal} Traversed the MAIN ROOT Directory of endpoint {client_id} on {timestamp}."
            else:
                return f"User {principal} Traversed the \"{path}\" directory of endpoint {client_id} on {timestamp}."

        elif msg_type == 'recursive_directory':
            client_id = match.group('client_id') if 'client_id' in match.groupdict() else self.extract_client_id(full_message, details)
            path = match.group('path') if 'path' in match.groupdict() else None
            depth = match.group('depth') if 'depth' in match.groupdict() else "0"

            if not path:
                path = self.extract_path_from_message(full_message)

            return f"User {principal} Recursively refreshed (Traversing) the {path} directory of endpoint {client_id} on {timestamp}."

        elif msg_type == 'registry_traversal':
            client_id = self.extract_client_id(full_message, details)
            path = self.extract_path_from_message(full_message)

            if not path:
                return f"User {principal} refreshed (Traversed) the Main Registry directory of endpoint {client_id} on {timestamp}."
            else:
                return f"User {principal} Traversed the {path} key of endpoint {client_id} on {timestamp}."

        elif msg_type == 'hunt_deletion':
            hunt_id = match.group('hunt_id') if 'hunt_id' in match.groupdict() else "unknown"
            return f"User {principal} deleted hunt {hunt_id} on {timestamp}."

        elif msg_type == 'recursive_download':
            principal = match.group('principal') if 'principal' in match.groupdict() else self._extract_principal(full_message)
            timestamp = self._extract_timestamp(full_message)
            client_id = self.extract_client_id(full_message)

            # Manually extract the components path string
            try:
                raw_path_match = re.search(r'key\\":\\"Components\\",\\"value\\":\\"(\[.*?\])\\"', full_message)
                if raw_path_match:
                    raw_path = raw_path_match.group(1)

                    # Remove the [ ] and split on commas
                    cleaned = raw_path.strip('[]')
                    parts = [p.strip().strip('\\"') for p in cleaned.split(',')]
                    path = '\\'.join(parts)
                else:
                    path = "<unknown path>"
            except Exception as e:
                logger.error(f"Error parsing recursive download path: {e}")
                path = "<unknown path>"

            return f"User {principal} recursively downloaded the folder \"{path}\" from endpoint {client_id} on {timestamp}."


        elif msg_type == 'user_create':
            username = match.group('username')
            _, roles = self.extract_user_info(full_message, details)
            roles_str = ", ".join(roles) if roles else "None"
            return f"User {principal} created a new user with username \"{username}\" and role(s): {roles_str} on {timestamp}."


        elif msg_type == 'user_grant':
            username, roles = self.extract_user_info(full_message, details)
            roles_str = ", ".join(roles) if roles else "None"

            # Check if this is a role removal by looking at specific role changes
            if "removed privileges" in full_message.lower() or len(roles) < 4:  # Heuristic check for role reduction
                return f"User {principal} removed privileges from user {username}, the new ACL for user {username} is, {roles_str} of org root on {timestamp}."
            else:
                return f"User {principal} Modified the {username} User's ACLs, the new user's roles are: {roles_str} of ORG root on {timestamp}."

        elif msg_type == 'set_artifact':
            artifact_name = self.extract_artifact_name(full_message, details)
            return f"User {principal} Created a new artifact with the title of \"{artifact_name}\" on {timestamp}."


        elif msg_type == 'directory_traversal_ntfs':
            principal = match.group('principal')
            client_id = self.extract_client_id_ntfs(full_message)
            path = self.extract_components_path_ntfs(full_message)
            return f"User {principal} Traversed NTFS directory \"{path}\" on endpoint {client_id} on {timestamp}."


        elif msg_type == 'recursive_directory_ntfs':
            principal = match.group('principal')
            depth = match.group('depth')
            client_id = self.extract_client_id_ntfs(full_message)
            path = self.extract_components_path_ntfs(full_message)
            return f"User {principal} Recursively Traversed NTFS directory \"{path}\" (depth {depth}) on endpoint {client_id} on {timestamp}."



        elif msg_type == 'recursive_download_ntfs':
            principal = match.group('principal')
            client_id = self.extract_client_id_ntfs(full_message)
            path = self.extract_components_path_ntfs(full_message)
            return f"User {principal} Recursively Downloaded NTFS folder \"{path}\" from endpoint {client_id} on {timestamp}."




        #elif msg_type == 'user_logon':
        #    user = match.group('user') if 'user' in match.groupdict() else principal
        #    return f"User {user} Just logged on, at {timestamp}."

        return None


    def _extract_timestamp(self, message):
        """Extract timestamp from message"""
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})', message)
        if timestamp_match:
            return timestamp_match.group(1)
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _extract_orgs(self, message, details=None):
        """Extract organizations from details JSON or message"""
        try:
            if details:
                details_dict = json.loads(details.replace('\\"', '"'))
                if 'orgs' in details_dict:
                    return ", ".join(details_dict['orgs'])
                elif 'org_ids' in details_dict:
                    return ", ".join(details_dict['org_ids'])

            # Try to extract from message
            orgs_match = re.search(r'\"org_ids\":\[(.*?)\]', message)
            if orgs_match:
                orgs_str = orgs_match.group(1)
                orgs = [org.strip('"') for org in orgs_str.split(',')]
                return ", ".join(orgs)

            return "root"
        except:
            return "root"


    def extract_components_path_ntfs(self, message):
        try:
            match = re.search(r'key\\":\\"Components\\",\\"value\\":\\"(\[.*?\])\\"', message)
            if match:
                raw = match.group(1)
                components = [p.strip().strip('\\"') for p in raw.strip("[]").split(",")]
                return '\\'.join(components)
        except Exception as e:
            logger.error(f"Error parsing NTFS path: {e}")
        return "<unknown path>"




    def send_email(self, subject, body):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config.sender_email
            msg['To'] = ', '.join(self.email_config.recipient_emails)

            if self.email_config.cc_emails:
                msg['Cc'] = ', '.join(self.email_config.cc_emails)

            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            recipients = self.email_config.recipient_emails + self.email_config.cc_emails

            with smtplib.SMTP(self.email_config.smtp_server, self.email_config.smtp_port) as server:
                if self.email_config.use_tls:
                    server.starttls()
                server.login(self.email_config.sender_email, self.email_config.sender_password)
                server.sendmail(self.email_config.sender_email, recipients, msg.as_string())

            logger.info(f"Email sent: {subject}")
        except Exception as e:
            logger.error(f"Error sending email: {e}")



def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Velociraptor Syslog Monitor and Email Notification System')
    parser.add_argument('--host', default='0.0.0.0', help='Host to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=514, help='UDP port to listen on (default: 514)')
    parser.add_argument('--smtp-server', required=True, help='SMTP server hostname')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP server port (default: 587)')
    parser.add_argument('--sender-email', required=True, help='Sender email address')
    parser.add_argument('--recipient-email', required=True, help='Recipient email address')
    parser.add_argument('--cc', help='Comma-separated list of CC recipients')
    parser.add_argument('--no-tls', action='store_true', help='Disable TLS for SMTP connection')
    parser.add_argument('--test', action='store_true', help='Run in test mode with sample messages')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # Set debug level if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    # Create message queue
    message_queue = queue.Queue()
    EMAIL_PASSWORD = "YOURPASSHERE"
    # Create email configuration
    email_config = EmailConfig(
        smtp_server=args.smtp_server,
        smtp_port=args.smtp_port,
        sender_email=args.sender_email,
        sender_password=EMAIL_PASSWORD,
        recipient_emails=args.recipient_email,
        cc_emails=args.cc,
        use_tls=not args.no_tls
)

    # Create message processor
    processor = MessageProcessor(message_queue, email_config)
    processor_thread = threading.Thread(target=processor.start)
    processor_thread.daemon = True
    processor_thread.start()

    try:
        if args.test:
            # Test mode with sample messages
            logger.info("Running in test mode with sample messages")

            # Load sample messages from file
            with open('velociraptor-syslog-key-logs.txt', 'r') as f:
                sample_messages = f.read().split('\n\n')

            for msg in sample_messages:
                if msg.strip():
                    logger.info(f"Processing sample message: {msg[:100]}...")
                    message_queue.put(msg)
                    time.sleep(1)

            # Wait for all messages to be processed
            message_queue.join()

            logger.info("Test completed")
        else:
            # Normal mode with UDP listener
            logger.info("Starting UDP listener")
            handler = SyslogUDPHandler(args.host, args.port, message_queue)
            handler_thread = threading.Thread(target=handler.start)
            handler_thread.daemon = True
            handler_thread.start()

            # Keep the main thread alive
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        # Clean up
        processor.stop()
        if 'handler' in locals():
            handler.stop()

if __name__ == "__main__":
    main()

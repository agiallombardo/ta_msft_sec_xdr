import import_declare_test
import json
import logging
import datetime
import sys
import ssl
import urllib
import os
from typing import Dict, Tuple
import requests
from requests.auth import HTTPBasicAuth

from solnlib import conf_manager, log
from splunklib import modularinput as smi
from solnlib.modular_input import checkpointer

ADDON_NAME = "ta_msft_sec_xdr"
GRAPH_ALERTS_URL = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
TOKEN_URL = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'
CHECKPOINTER = "ta_msft_sec_xdr_checkpoints"
DEFAULT_PAGE_SIZE = 100

def get_log_level(session_key: str) -> int:
    """Get the log level from the add-on settings.
    
    Args:
        session_key: Splunk session key
        
    Returns:
        The log level as an integer (logging.INFO, logging.DEBUG, etc.)
    """
    try:
        # Get the settings configuration
        settings_cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-ta_msft_sec_xdr_settings".format(ADDON_NAME)
        )
        
        # Get the logging stanza
        settings_conf = settings_cfm.get_conf("ta_msft_sec_xdr_settings")
        log_level_str = settings_conf.get("logging", {}).get("loglevel", "INFO")
        
        # Convert string log level to logging constant
        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        return log_levels.get(log_level_str, logging.INFO)
    except Exception:
        # Default to INFO if there's any error
        return logging.INFO

def logger_for_input(session_key: str, input_name: str) -> logging.Logger:
    """Set up a logger instance for the input.
    
    Logs are stored in $SPLUNK_HOME/var/log/splunk/ta_msft_sec_xdr_*.log
    The log level is determined by the add-on settings (Configuration > Logging)
    """
    # Set up the log directory to ensure logs go to the right place
    try:
        log_dir = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'log', 'splunk')
        log.Logs.set_context(directory=log_dir, namespace=ADDON_NAME.lower())
    except Exception:
        # If we can't set the context, the solnlib will try to use the default location
        pass
    
    # Create a safe name for the logger
    safe_input_name = input_name.replace(" ", "_").replace(":", "_").replace("/", "_").replace("\\", "_")
    logger_name = f"{safe_input_name}"
    
    # Get the logger and set the log level from settings
    logger = log.Logs().get_logger(logger_name)
    log_level = get_log_level(session_key)
    logger.setLevel(log_level)
    
    return logger

def get_account_credentials(session_key: str, account_name: str) -> Dict[str, str]:
    """Get account credentials from Splunk configuration."""
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_msft_sec_xdr_account",
    )
    account_conf_file = cfm.get_conf("ta_msft_sec_xdr_account")
    account = account_conf_file.get(account_name, None)
    if not account:
        return {}
    credentials = {
        "tenant": account.get("tenant"),
        "client_id": account.get("clientid"),
        "client_secret": account.get("apitoken")
    }
    return credentials

def get_checkpoint(logger, session_key, checkpoint_name, addon_name, datetime_format):
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, addon_name
        )
        checkpoint_data = checkpoint_collection.get(checkpoint_name)
        if(checkpoint_data):
            return True, checkpoint_data.get("start_time")
        else:
            return True, datetime.datetime.strftime(datetime.datetime.strptime('1970-01-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ'), datetime_format)
    except Exception as e:
        logger.error(f"Error in Checkpoint handling: {e}")
        return False, None

def set_checkpoint(logger, session_key, checkpoint_name, addon_name, new_checkpoint):
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, addon_name
        )
        checkpoint_collection.update(checkpoint_name, {'start_time':new_checkpoint})
    except Exception as e:
        logger.error(f"Error in Checkpoint handling: {e}")

def get_access_token(credentials: Dict[str, str]) -> str:
    """Get OAuth access token from Microsoft Graph."""
    data = {
        'client_id': credentials.get('client_id'),
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': credentials.get('client_secret'),
        'grant_type': 'client_credentials'
    }
    
    url = TOKEN_URL.format(credentials.get('tenant'))
    response = requests.post(url, data=data)
    
    if response.status_code != 200:
        raise Exception(f"Failed to get access token: {response.text}")
        
    return response.json().get('access_token')

def get_data_from_api(logger, ew, index, session_key, input_name, input_item):
    account_name = input_item.get("account")
    credentials = get_account_credentials(session_key, account_name)
    if not credentials:
        logger.error(f"Failed to get credentials for account {account_name}")
        return False

    CheckpointID = f'{account_name}-{input_name}-last_runtime'.replace("://", "_")
    api_datetime_format = TIME_FORMAT
    checkpoint_valid, checkpoint_date = get_checkpoint(logger, session_key, CheckpointID, ADDON_NAME, api_datetime_format)
    
    if not checkpoint_valid:
        return False

    new_checkpoint = datetime.datetime.utcnow().strftime(api_datetime_format)
    
    try:
        # Get OAuth token
        access_token = get_access_token(credentials)
        logger.info("Successfully obtained access token")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        params = {
            '$filter': f'lastUpdateDateTime gt {checkpoint_date} and lastUpdateDateTime lt {new_checkpoint}'
        }
        
        logger.info(f"Sending API request from {checkpoint_date} to current run time")
        logger.info(f"Request URL: {GRAPH_ALERTS_URL}")
        logger.info(f"Request headers: {json.dumps({k: '***' if k == 'Authorization' else v for k, v in headers.items()})}")
        logger.info(f"Request params: {json.dumps(params)}")
        
        # Initial request
        response = requests.get(url=GRAPH_ALERTS_URL, params=params, headers=headers)
        logger.info(f"API Response Code: {response.status_code}")
        
        if response.status_code == 400:
            logger.error(f"Bad Request (400) - Response body: {response.text}")
            logger.error(f"Request URL: {response.url}")
            logger.error(f"Request headers: {json.dumps({k: '***' if k == 'Authorization' else v for k, v in headers.items()})}")
            logger.error(f"Request params: {json.dumps(params)}")
            return False
        elif response.status_code == 403:
            logger.error("Permission denied. Ensure the app has SecurityAlert.Read.All permission")
            logger.error(f"Response body: {response.text}")
            return False
        elif response.status_code != 200:
            logger.error(f"API request failed with status code {response.status_code}")
            logger.error(f"Response body: {response.text}")
            return False

        data = response.json()
        alerts = data.get('value', [])
        
        logger.info(f"Total Alerts: {len(alerts)}")

        # Process initial page of alerts
        if alerts:
            for alert in alerts:
                try:
                    updatedate = datetime.datetime.strptime(alert.get('lastUpdateDateTime', ''), api_datetime_format)
                except:
                    logger.warn("no 'lastUpdateDateTime' found, defaulting to now()")
                    updatedate = datetime.datetime.utcnow()
                    
                ew.write_event(
                    smi.Event(
                        data=json.dumps(alert),
                        index=index,
                        sourcetype=input_item.get("sourcetype", "GraphSecurityAlert:V2"),
                        time=updatedate.timestamp()
                    )
                )

        # Handle paging
        while "@odata.nextLink" in data:
            next_link = data["@odata.nextLink"]
            logger.info(f"Fetching next page of results")
            logger.info(f"Next page URL: {next_link}")
            
            response = requests.get(url=next_link, headers=headers)
            if response.status_code != 200:
                logger.error(f"Failed to get next page: {response.status_code}")
                logger.error(f"Response body: {response.text}")
                break
                
            data = response.json()
            alerts = data.get('value', [])
            logger.info(f"Alerts in next page: {len(alerts)}")
            
            for alert in alerts:
                try:
                    updatedate = datetime.datetime.strptime(alert.get('lastUpdateDateTime', ''), api_datetime_format)
                except:
                    logger.warn("no 'lastUpdateDateTime' found, defaulting to now()")
                    updatedate = datetime.datetime.utcnow()
                    
                ew.write_event(
                    smi.Event(
                        data=json.dumps(alert),
                        index=index,
                        sourcetype=input_item.get("sourcetype", "GraphSecurityAlert:V2"),
                        time=updatedate.timestamp()
                    )
                )
            
        set_checkpoint(logger, session_key, CheckpointID, ADDON_NAME, new_checkpoint)
        return True

    except Exception as e:
        logger.error(f"Error collecting alerts: {str(e)}", exc_info=True)
        return False

class DefenderXDRAlertInputs(smi.Script):
    def __init__(self):
        super(DefenderXDRAlertInputs, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme("Microsoft Defender XDR Alert Inputs")
        scheme.description = "Collects security alerts from Microsoft Defender XDR via Graph API"
        scheme.use_external_validation = True
        scheme.use_single_instance = False
        scheme.streaming_mode_xml = True

        name = smi.Argument("name")
        name.title = "Name"
        name.description = "Name"
        name.required_on_create = True
        scheme.add_argument(name)

        account = smi.Argument("account")
        account.title = "Account"
        account.description = "Select the account to use for connecting to Microsoft Graph API"
        account.required_on_create = True
        scheme.add_argument(account)

        return scheme
        
    def validate_input(self, definition: smi.ValidationDefinition):
        return 

    def stream_events(self, inputs, event_writer):
        for input_name, input_item in inputs.inputs.items():
            normalized_input_name = input_name.split("/")[-1]
            session_key = inputs.metadata["session_key"]
            logger = logger_for_input(session_key, normalized_input_name)
            try:
                success = get_data_from_api(logger, event_writer, input_item.get("index"), session_key, normalized_input_name, input_item)
                logger.info(f"Successfully ran input {normalized_input_name}" if success else "Finished execution unsuccessfully")
            except Exception as e:
                logger.error(f"Error in stream_events for input {normalized_input_name}: {e}", exc_info=True)

if __name__ == "__main__":
    exit_code = DefenderXDRAlertInputs().run(sys.argv)
    sys.exit(exit_code)
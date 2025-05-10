# Microsoft Defender XDR Add-on for Splunk

## Overview
This add-on collects security data from Microsoft Defender XDR via the Microsoft Graph API and ingests it into Splunk. It enables security teams to analyze, correlate, and respond to security alerts from Microsoft's security products within their Splunk environment.

## User Guide

### Prerequisites
- Splunk Enterprise or Splunk Cloud
- Microsoft 365 E5 Security or Microsoft Defender for Endpoint P2 license
- Azure AD application with appropriate permissions
- Network connectivity from your Splunk instance to Microsoft Graph API endpoints

### Installation
1. Install the add-on through Splunkbase or manually by extracting the package to `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk or use the web interface to install the add-on
3. Configure the add-on with your Microsoft Graph API credentials
4. Set up data inputs

### Configuration
#### Step 1: Create an Azure AD Application
1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Enter a name for your application (e.g., "Splunk Microsoft Defender XDR Integration")
4. Select "Accounts in this organizational directory only" for Supported account types
5. Leave Redirect URI blank
6. Click "Register"
7. Note the Application (client) ID and Directory (tenant) ID from the overview page

#### Step 2: Create a Client Secret
1. In your newly created app registration, go to "Certificates & secrets"
2. Click "New client secret"
3. Add a description and select an expiration period
4. Click "Add"
5. **Important**: Copy the client secret value immediately as it won't be visible again

#### Step 3: Grant API Permissions
1. Go to "API permissions"
2. Click "Add a permission"
3. Select "Microsoft Graph"
4. Choose "Application permissions"
5. Search for and select the following permissions:
   - SecurityEvents.Read.All
   - SecurityAlert.Read.All
6. Click "Add permissions"
7. Click "Grant admin consent for [your organization]"

#### Step 4: Configure the Add-on in Splunk
1. Go to Splunk > Apps > Microsoft Defender XDR Add-on > Configuration
2. Navigate to the "Account" tab
3. Click "Add" to create a new account
4. Enter the following information:
   - Account name: A unique name for this connection
   - Tenant ID: Your Azure AD tenant ID
   - Client ID: Your Azure AD application client ID
   - Client Secret: Your Azure AD application client secret
5. Click "Save"

#### Step 5: Set up Data Inputs
1. Go to Splunk > Apps > Microsoft Defender XDR Add-on > Inputs
2. Click "Create New Input"
3. Select "Microsoft Defender XDR Alert Inputs"
4. Configure the input:
   - Name: A unique name for this input
   - Interval: How frequently to collect data (in seconds)
   - Index: The Splunk index where the data should be stored
   - Account: Select the account you created in Step 4
5. Click "Save"

### Data Types
This add-on collects the following types of data:

#### Security Alerts (GraphSecurityAlert:V2)
Security alerts from Microsoft Defender XDR, including:
- Alert ID and title
- Severity and category
- Affected resources
- Detection source
- Status and assignment information
- MITRE ATT&CK techniques

### Troubleshooting

#### Common Issues

##### Authentication Failures
- **Symptom**: Errors in logs indicating "Failed to get access token"
- **Possible Causes**:
  - Incorrect tenant ID, client ID, or client secret
  - Expired client secret
  - Insufficient permissions
- **Solution**:
  - Verify credentials in the add-on configuration
  - Check if the client secret has expired and create a new one if needed
  - Ensure proper permissions are granted and admin consent is provided

##### No Data Being Collected
- **Symptom**: Input runs successfully but no events appear in Splunk
- **Possible Causes**:
  - No new alerts in the time period
  - Filter issues
  - Checkpoint issues
- **Solution**:
  - Verify alerts exist in the Microsoft 365 Defender portal
  - Check the add-on logs for filtering details
  - Reset the checkpoint by deleting the KVStore entry

##### API Rate Limiting
- **Symptom**: Errors indicating "Too many requests" or HTTP 429 status codes
- **Possible Causes**:
  - Exceeding Microsoft Graph API rate limits
- **Solution**:
  - Increase the input interval
  - Implement exponential backoff (in future versions)

### Logging
- Logs are stored in `$SPLUNK_HOME/var/log/splunk/ta_msft_sec_xdr_*.log`
- Set the log level in the add-on settings (Configuration > Logging)
- For detailed troubleshooting, set the log level to DEBUG

### Performance Tuning
- For environments with many alerts, increase the collection interval to reduce API load
- Default interval is 300 seconds (5 minutes)
- Recommended minimum interval: 60 seconds
- For large environments: 600-900 seconds (10-15 minutes)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE.md) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

© 2025 Anthony Giallombardo, NullQu LLC.

## Contact

Created by Anthony Giallombardo - Anthony at NullQu com

from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging

# MCP
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

mcp = FastMCP(
    "google-ads-server",
    dependencies=[
        "google-auth-oauthlib",
        "google-auth",
        "requests",
        "python-dotenv"
    ]
)

# Constants and configuration
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"  # Google Ads API version

# Load environment variables
try:
    from dotenv import load_dotenv
    # Load from .env file if it exists
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Get credentials from environment variables
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # oauth or service_account

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    # Convert to string if passed as integer or another type
    customer_id = str(customer_id)
    
    # Remove any quotes surrounding the customer_id (both escaped and unescaped)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    
    # Remove any non-digit characters (including dashes, braces, etc.)
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    
    # Ensure it's 10 digits with leading zeros if needed
    return customer_id.zfill(10)

def get_credentials():
    """
    Get and refresh OAuth credentials or service account credentials based on the auth type.
    
    This function supports two authentication methods:
    1. OAuth 2.0 (User Authentication) - For individual users or desktop applications
    2. Service Account (Server-to-Server Authentication) - For automated systems

    Returns:
        Valid credentials object to use with Google Ads API
    """
    if not GOOGLE_ADS_CREDENTIALS_PATH:
        raise ValueError("GOOGLE_ADS_CREDENTIALS_PATH environment variable not set")
    
    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logger.info(f"Using authentication type: {auth_type}")
    
    # Service Account authentication
    if auth_type == "service_account":
        try:
            return get_service_account_credentials()
        except Exception as e:
            logger.error(f"Error with service account authentication: {str(e)}")
            raise
    
    # OAuth 2.0 authentication (default)
    return get_oauth_credentials()

def get_service_account_credentials():
    """Get credentials using a service account key file."""
    logger.info(f"Loading service account credentials from {GOOGLE_ADS_CREDENTIALS_PATH}")
    
    if not os.path.exists(GOOGLE_ADS_CREDENTIALS_PATH):
        raise FileNotFoundError(f"Service account key file not found at {GOOGLE_ADS_CREDENTIALS_PATH}")
    
    try:
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_ADS_CREDENTIALS_PATH, 
            scopes=SCOPES
        )
        
        # Check if impersonation is required
        impersonation_email = os.environ.get("GOOGLE_ADS_IMPERSONATION_EMAIL")
        if impersonation_email:
            logger.info(f"Impersonating user: {impersonation_email}")
            credentials = credentials.with_subject(impersonation_email)
            
        return credentials
        
    except Exception as e:
        logger.error(f"Error loading service account credentials: {str(e)}")
        raise

def get_oauth_credentials():
    """Get and refresh OAuth user credentials."""
    creds = None
    client_config = None
    
    # Path to store the refreshed token
    token_path = GOOGLE_ADS_CREDENTIALS_PATH
    if os.path.exists(token_path) and not os.path.basename(token_path).endswith('.json'):
        # If it's not explicitly a .json file, append a default name
        token_dir = os.path.dirname(token_path)
        token_path = os.path.join(token_dir, 'google_ads_token.json')
    
    # Check if token file exists and load credentials
    if os.path.exists(token_path):
        try:
            logger.info(f"Loading OAuth credentials from {token_path}")
            with open(token_path, 'r') as f:
                creds_data = json.load(f)
                # Check if this is a client config or saved credentials
                if "installed" in creds_data or "web" in creds_data:
                    client_config = creds_data
                    logger.info("Found OAuth client configuration")
                else:
                    logger.info("Found existing OAuth token")
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in token file: {token_path}")
            creds = None
        except Exception as e:
            logger.warning(f"Error loading credentials: {str(e)}")
            creds = None
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.info("Refreshing expired token")
                creds.refresh(Request())
                logger.info("Token successfully refreshed")
            except RefreshError as e:
                logger.warning(f"Error refreshing token: {str(e)}, will try to get new token")
                creds = None
            except Exception as e:
                logger.error(f"Unexpected error refreshing token: {str(e)}")
                raise
        
        # If we need new credentials
        if not creds:
            # If no client_config is defined yet, create one from environment variables
            if not client_config:
                logger.info("Creating OAuth client config from environment variables")
                client_id = os.environ.get("GOOGLE_ADS_CLIENT_ID")
                client_secret = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")
                
                if not client_id or not client_secret:
                    raise ValueError("GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set if no client config file exists")
                
                client_config = {
                    "installed": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                }
            
            # Run the OAuth flow
            logger.info("Starting OAuth authentication flow")
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
            logger.info("OAuth flow completed successfully")
        
        # Save the refreshed/new credentials
        try:
            logger.info(f"Saving credentials to {token_path}")
            # Ensure directory exists
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            with open(token_path, 'w') as f:
                f.write(creds.to_json())
        except Exception as e:
            logger.warning(f"Could not save credentials: {str(e)}")
    
    return creds

def get_headers(creds):
    """Get headers for Google Ads API requests."""
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    # Handle different credential types
    if isinstance(creds, service_account.Credentials):
        # For service account, we need to get a new bearer token
        auth_req = Request()
        creds.refresh(auth_req)
        token = creds.token
    else:
        # For OAuth credentials, check if token needs refresh
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                try:
                    logger.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                    logger.info("Token successfully refreshed in get_headers")
                except RefreshError as e:
                    logger.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error refreshing token in get_headers: {str(e)}")
                    raise
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")
        
        token = creds.token
        
    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }
    
    if GOOGLE_ADS_LOGIN_CUSTOMER_ID:
        headers['login-customer-id'] = format_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
    
    return headers

@mcp.tool()
async def list_accounts() -> str:
    """
    Lists all accessible Google Ads accounts.
    
    This is typically the first command you should run to identify which accounts 
    you have access to. The returned account IDs can be used in subsequent commands.
    
    Returns:
        A formatted list of all Google Ads accounts accessible with your credentials
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        # Format the results
        result_lines = ["Accessible Google Ads Accounts:"]
        result_lines.append("-" * 50)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax")
) -> str:
    """
    Execute a custom GAQL (Google Ads Query Language) query.
    
    This tool allows you to run any valid GAQL query against the Google Ads API.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        query: The GAQL query to execute (must follow GAQL syntax)
        
    Returns:
        Formatted query results or error message
        
    Example:
        customer_id: "1234567890"
        query: "SELECT campaign.id, campaign.name FROM campaign LIMIT 10"
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        # Format the results as a table
        result_lines = [f"Query Results for Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        # Get field names from the first result
        fields = []
        first_result = results['results'][0]
        for key in first_result:
            if isinstance(first_result[key], dict):
                for subkey in first_result[key]:
                    fields.append(f"{key}.{subkey}")
            else:
                fields.append(key)
        
        # Add header
        result_lines.append(" | ".join(fields))
        result_lines.append("-" * 80)
        
        # Add data rows
        for result in results['results']:
            row_data = []
            for field in fields:
                if "." in field:
                    parent, child = field.split(".")
                    value = str(result.get(parent, {}).get(child, ""))
                else:
                    value = str(result.get(field, ""))
                row_data.append(value)
            result_lines.append(" | ".join(row_data))
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)")
) -> str:
    """
    Get campaign performance metrics for the specified time period.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_account_currency() to see what currency the account uses
    3. Finally run this command to get campaign performance
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Formatted table of campaign performance data
        
    Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.average_cpc
        FROM campaign
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.cost_micros DESC
        LIMIT 50
    """
    
    return await execute_gaql_query(customer_id, query)

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)")
) -> str:
    """
    Get ad performance metrics for the specified time period.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_account_currency() to see what currency the account uses
    3. Finally run this command to get ad performance
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Formatted table of ad performance data
        
    Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    query = f"""
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.status,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group_ad
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 50
    """
    
    return await execute_gaql_query(customer_id, query)

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'")
) -> str:
    """
    Execute any arbitrary GAQL (Google Ads Query Language) query with custom formatting options.
    
    This is the most powerful tool for custom Google Ads data queries.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        query: The GAQL query to execute (any valid GAQL query)
        format: Output format ("table", "json", or "csv")
    
    Returns:
        Query results in the requested format
    
    EXAMPLE QUERIES:
    
    1. Basic campaign metrics:
        SELECT 
          campaign.name, 
          metrics.clicks, 
          metrics.impressions,
          metrics.cost_micros
        FROM campaign 
        WHERE segments.date DURING LAST_7_DAYS
    
    2. Ad group performance:
        SELECT 
          ad_group.name, 
          metrics.conversions, 
          metrics.cost_micros,
          campaign.name
        FROM ad_group 
        WHERE metrics.clicks > 100
    
    3. Keyword analysis:
        SELECT 
          keyword.text, 
          metrics.average_position, 
          metrics.ctr
        FROM keyword_view 
        ORDER BY metrics.impressions DESC
        
    4. Get conversion data:
        SELECT
          campaign.name,
          metrics.conversions,
          metrics.conversions_value,
          metrics.cost_micros
        FROM campaign
        WHERE segments.date DURING LAST_30_DAYS
        
            Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        if format.lower() == "json":
            return json.dumps(results, indent=2)
        
        elif format.lower() == "csv":
            # Get field names from the first result
            fields = []
            first_result = results['results'][0]
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        fields.append(f"{key}.{subkey}")
                else:
                    fields.append(key)
            
            # Create CSV string
            csv_lines = [",".join(fields)]
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, "")).replace(",", ";")
                    else:
                        value = str(result.get(field, "")).replace(",", ";")
                    row_data.append(value)
                csv_lines.append(",".join(row_data))
            
            return "\n".join(csv_lines)
        
        else:  # default table format
            result_lines = [f"Query Results for Account {formatted_customer_id}:"]
            result_lines.append("-" * 100)
            
            # Get field names and maximum widths
            fields = []
            field_widths = {}
            first_result = results['results'][0]
            
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        field = f"{key}.{subkey}"
                        fields.append(field)
                        field_widths[field] = len(field)
                else:
                    fields.append(key)
                    field_widths[key] = len(key)
            
            # Calculate maximum field widths
            for result in results['results']:
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    field_widths[field] = max(field_widths[field], len(value))
            
            # Create formatted header
            header = " | ".join(f"{field:{field_widths[field]}}" for field in fields)
            result_lines.append(header)
            result_lines.append("-" * len(header))
            
            # Add data rows
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    row_data.append(f"{value:{field_widths[field]}}")
                result_lines.append(" | ".join(row_data))
            
            return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_ad_creatives(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'")
) -> str:
    """
    Get ad creative details including headlines, descriptions, and URLs.
    
    This tool retrieves the actual ad content (headlines, descriptions) 
    for review and analysis. Great for creative audits.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run this command with the desired account ID
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        
    Returns:
        Formatted list of ad creative details
        
    Example:
        customer_id: "1234567890"
    """
    query = """
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.ad.type,
            ad_group_ad.ad.final_urls,
            ad_group_ad.status,
            ad_group_ad.ad.responsive_search_ad.headlines,
            ad_group_ad.ad.responsive_search_ad.descriptions,
            ad_group.name,
            campaign.name
        FROM ad_group_ad
        WHERE ad_group_ad.status != 'REMOVED'
        ORDER BY campaign.name, ad_group.name
        LIMIT 50
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving ad creatives: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No ad creatives found for this customer ID."
        
        # Format the results in a readable way
        output_lines = [f"Ad Creatives for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            ad = result.get('adGroupAd', {}).get('ad', {})
            ad_group = result.get('adGroup', {})
            campaign = result.get('campaign', {})
            
            output_lines.append(f"\n{i}. Campaign: {campaign.get('name', 'N/A')}")
            output_lines.append(f"   Ad Group: {ad_group.get('name', 'N/A')}")
            output_lines.append(f"   Ad ID: {ad.get('id', 'N/A')}")
            output_lines.append(f"   Ad Name: {ad.get('name', 'N/A')}")
            output_lines.append(f"   Status: {result.get('adGroupAd', {}).get('status', 'N/A')}")
            output_lines.append(f"   Type: {ad.get('type', 'N/A')}")
            
            # Handle Responsive Search Ads
            rsa = ad.get('responsiveSearchAd', {})
            if rsa:
                if 'headlines' in rsa:
                    output_lines.append("   Headlines:")
                    for headline in rsa['headlines']:
                        output_lines.append(f"     - {headline.get('text', 'N/A')}")
                
                if 'descriptions' in rsa:
                    output_lines.append("   Descriptions:")
                    for desc in rsa['descriptions']:
                        output_lines.append(f"     - {desc.get('text', 'N/A')}")
            
            # Handle Final URLs
            final_urls = ad.get('finalUrls', [])
            if final_urls:
                output_lines.append(f"   Final URLs: {', '.join(final_urls)}")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'")
) -> str:
    """
    Retrieve the default currency code used by the Google Ads account.
    
    IMPORTANT: Run this first before analyzing cost data to understand which currency
    the account uses. Cost values are always displayed in the account's currency.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
    
    Returns:
        The account's default currency code (e.g., 'USD', 'EUR', 'GBP')
        
    Example:
        customer_id: "1234567890"
    """
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    
    try:
        creds = get_credentials()
        
        # Force refresh if needed
        if not creds.valid:
            logger.info("Credentials not valid, attempting refresh...")
            if hasattr(creds, 'refresh_token') and creds.refresh_token:
                creds.refresh(Request())
                logger.info("Credentials refreshed successfully")
            else:
                raise ValueError("Invalid credentials and no refresh token available")
        
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving account currency: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer ID."
        
        # Extract the currency code from the results
        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        
        return f"Account {formatted_customer_id} uses currency: {currency_code}"
    
    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    """Google Ads Query Language (GAQL) reference documentation."""
    return """
    # Google Ads Query Language (GAQL) Reference
    
    GAQL is similar to SQL but with specific syntax for Google Ads. Here's a quick reference:
    
    ## Basic Query Structure
    ```
    SELECT field1, field2, ... 
    FROM resource_type
    WHERE condition
    ORDER BY field [ASC|DESC]
    LIMIT n
    ```
    
    ## Common Field Types
    
    ### Resource Fields
    - campaign.id, campaign.name, campaign.status
    - ad_group.id, ad_group.name, ad_group.status
    - ad_group_ad.ad.id, ad_group_ad.ad.final_urls
    - keyword.text, keyword.match_type
    
    ### Metric Fields
    - metrics.impressions
    - metrics.clicks
    - metrics.cost_micros
    - metrics.conversions
    - metrics.ctr
    - metrics.average_cpc
    
    ### Segment Fields
    - segments.date
    - segments.device
    - segments.day_of_week
    
    ## Common WHERE Clauses
    
    ### Date Ranges
    - WHERE segments.date DURING LAST_7_DAYS
    - WHERE segments.date DURING LAST_30_DAYS
    - WHERE segments.date BETWEEN '2023-01-01' AND '2023-01-31'
    
    ### Filtering
    - WHERE campaign.status = 'ENABLED'
    - WHERE metrics.clicks > 100
    - WHERE campaign.name LIKE '%Brand%'
    
    ## Tips
    - Always check account currency before analyzing cost data
    - Cost values are in micros (millionths): 1000000 = 1 unit of currency
    - Use LIMIT to avoid large result sets
    """

@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    """Provides guidance on the recommended workflow for using Google Ads tools."""
    return """
    I'll help you analyze your Google Ads account data. Here's the recommended workflow:
    
    1. First, let's list all the accounts you have access to:
       - Run the `list_accounts()` tool to get available account IDs
    
    2. Before analyzing cost data, let's check which currency the account uses:
       - Run `get_account_currency(customer_id="ACCOUNT_ID")` with your selected account
    
    3. Now we can explore the account data:
       - For campaign performance: `get_campaign_performance(customer_id="ACCOUNT_ID", days=30)`
       - For ad performance: `get_ad_performance(customer_id="ACCOUNT_ID", days=30)`
       - For ad creative review: `get_ad_creatives(customer_id="ACCOUNT_ID")`
    
    4. For custom queries, use the GAQL query tool:
       - `run_gaql(customer_id="ACCOUNT_ID", query="YOUR_QUERY", format="table")`
    
    5. Let me know if you have specific questions about:
       - Campaign performance
       - Ad performance
       - Keywords
       - Budgets
       - Conversions
    
    Important: Always provide the customer_id as a string.
    For example: customer_id="1234567890"
    """

@mcp.prompt("gaql_help")
def gaql_help() -> str:
    """Provides assistance for writing GAQL queries."""
    return """
    I'll help you write a Google Ads Query Language (GAQL) query. Here are some examples to get you started:
    
    ## Get campaign performance last 30 days
    ```
    SELECT
      campaign.id,
      campaign.name,
      campaign.status,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions
    FROM campaign
    WHERE segments.date DURING LAST_30_DAYS
    ORDER BY metrics.cost_micros DESC
    ```
    
    ## Get keyword performance
    ```
    SELECT
      keyword.text,
      keyword.match_type,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions
    FROM keyword_view
    WHERE segments.date DURING LAST_30_DAYS
    ORDER BY metrics.clicks DESC
    ```
    
    ## Get ads with poor performance
    ```
    SELECT
      ad_group_ad.ad.id,
      ad_group_ad.ad.name,
      campaign.name,
      ad_group.name,
      metrics.impressions,
      metrics.clicks,
      metrics.conversions
    FROM ad_group_ad
    WHERE 
      segments.date DURING LAST_30_DAYS
      AND metrics.impressions > 1000
      AND metrics.ctr < 0.01
    ORDER BY metrics.impressions DESC
    ```
    
    Once you've chosen a query, use it with:
    ```
    run_gaql(customer_id="YOUR_ACCOUNT_ID", query="YOUR_QUERY_HERE")
    ```
    
    Remember:
    - Always provide the customer_id as a string
    - Cost values are in micros (1,000,000 = 1 unit of currency)
    - Use LIMIT to avoid large result sets
    - Check the account currency before analyzing cost data
    """

@mcp.tool()
async def get_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    limit: int = Field(default=50, description="Maximum number of image assets to return")
) -> str:
    """
    Retrieve all image assets in the account including their full-size URLs.
    
    This tool allows you to get details about image assets used in your Google Ads account,
    including the URLs to download the full-size images for further processing or analysis.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run this command with the desired account ID
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        limit: Maximum number of image assets to return (default: 50)
        
    Returns:
        Formatted list of image assets with their download URLs
        
    Example:
        customer_id: "1234567890"
        limit: 100
    """
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
        LIMIT {limit}
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image assets found for this customer ID."
        
        # Format the results in a readable way
        output_lines = [f"Image Assets for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            asset = result.get('asset', {})
            image_asset = asset.get('imageAsset', {})
            full_size = image_asset.get('fullSize', {})
            
            output_lines.append(f"\n{i}. Asset ID: {asset.get('id', 'N/A')}")
            output_lines.append(f"   Name: {asset.get('name', 'N/A')}")
            
            if full_size:
                output_lines.append(f"   Image URL: {full_size.get('url', 'N/A')}")
                output_lines.append(f"   Dimensions: {full_size.get('widthPixels', 'N/A')} x {full_size.get('heightPixels', 'N/A')} px")
            
            file_size = image_asset.get('fileSize', 'N/A')
            if file_size != 'N/A':
                # Convert to KB for readability
                file_size_kb = int(file_size) / 1024
                output_lines.append(f"   File Size: {file_size_kb:.2f} KB")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def download_image_asset(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image")
) -> str:
    """
    Download a specific image asset from a Google Ads account.
    
    This tool allows you to download the full-size version of an image asset
    for further processing, analysis, or backup.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_image_assets() to get available image asset IDs
    3. Finally use this command to download specific images
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: The ID of the image asset to download
        output_dir: Directory where the image should be saved (default: ./ad_images)
        
    Returns:
        Status message indicating success or failure of the download
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        output_dir: "./my_ad_images"
    """
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
            AND asset.id = {asset_id}
        LIMIT 1
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image asset: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"
        
        # Extract the image URL
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"
        
        # Validate and sanitize the output directory to prevent path traversal
        try:
            # Get the base directory (current working directory)
            base_dir = Path.cwd()
            # Resolve the output directory to an absolute path
            resolved_output_dir = Path(output_dir).resolve()
            
            # Ensure the resolved path is within or under the current working directory
            # This prevents path traversal attacks like "../../../etc"
            try:
                resolved_output_dir.relative_to(base_dir)
            except ValueError:
                # If the path is not relative to base_dir, use the default safe directory
                resolved_output_dir = base_dir / "ad_images"
                logger.warning(f"Invalid output directory '{output_dir}' - using default './ad_images'")
            
            # Create output directory if it doesn't exist
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            return f"Error creating output directory: {str(e)}"
        
        # Download the image
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        # Clean the filename to be safe for filesystem
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = resolved_output_dir / filename
        
        # Save the image
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"Successfully downloaded image asset {asset_id} to {file_path}"
    
    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(default=None, description="Optional: specific asset ID to look up (leave empty to get all image assets)"),
    asset_type: str = Field(default="IMAGE", description="Asset type to search for ('IMAGE', 'TEXT', 'VIDEO', etc.)")
) -> str:
    """
    Find where specific assets are being used in campaigns, ad groups, and ads.
    
    This tool helps you analyze how assets are linked to campaigns and ads across your account,
    which is useful for creative analysis and optimization.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Run get_image_assets() to see available assets
    3. Use this command to see where specific assets are used
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: Optional specific asset ID to look up (leave empty to get all assets of the specified type)
        asset_type: Type of asset to search for (default: 'IMAGE')
        
    Returns:
        Formatted report showing where assets are used in the account
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        asset_type: "IMAGE"
    """
    # Build the query based on whether a specific asset ID was provided
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"
    
    # First get the assets themselves
    assets_query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type
        FROM
            asset
        WHERE
            {where_clause}
        LIMIT 100
    """
    
    # Then get the associations between assets and campaigns/ad groups
    # Try using campaign_asset instead of asset_link
    associations_query = f"""
        SELECT
            campaign.id,
            campaign.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            campaign_asset
        WHERE
            {where_clause}
        LIMIT 500
    """

    # Also try ad_group_asset for ad group level information
    ad_group_query = f"""
        SELECT
            ad_group.id,
            ad_group.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            ad_group_asset
        WHERE
            {where_clause}
        LIMIT 500
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        
        # First get the assets
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        payload = {"query": assets_query}
        assets_response = requests.post(url, headers=headers, json=payload)
        
        if assets_response.status_code != 200:
            return f"Error retrieving assets: {assets_response.text}"
        
        assets_results = assets_response.json()
        if not assets_results.get('results'):
            return f"No {asset_type} assets found for this customer ID."
        
        # Now get the associations
        payload = {"query": associations_query}
        assoc_response = requests.post(url, headers=headers, json=payload)
        
        if assoc_response.status_code != 200:
            return f"Error retrieving asset associations: {assoc_response.text}"
        
        assoc_results = assoc_response.json()
        
        # Format the results in a readable way
        output_lines = [f"Asset Usage for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        # Create a dictionary to organize asset usage by asset ID
        asset_usage = {}
        
        # Initialize the asset usage dictionary with basic asset info
        for result in assets_results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            if asset_id:
                asset_usage[asset_id] = {
                    'name': asset.get('name', 'Unnamed asset'),
                    'type': asset.get('type', 'Unknown'),
                    'usage': []
                }
        
        # Add usage information from the associations
        for result in assoc_results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            
            if asset_id and asset_id in asset_usage:
                campaign = result.get('campaign', {})
                ad_group = result.get('adGroup', {})
                ad = result.get('adGroupAd', {}).get('ad', {}) if 'adGroupAd' in result else {}
                asset_link = result.get('assetLink', {})
                
                usage_info = {
                    'campaign_id': campaign.get('id', 'N/A'),
                    'campaign_name': campaign.get('name', 'N/A'),
                    'ad_group_id': ad_group.get('id', 'N/A'),
                    'ad_group_name': ad_group.get('name', 'N/A'),
                    'ad_id': ad.get('id', 'N/A') if ad else 'N/A',
                    'ad_name': ad.get('name', 'N/A') if ad else 'N/A'
                }
                
                asset_usage[asset_id]['usage'].append(usage_info)
        
        # Format the output
        for asset_id, info in asset_usage.items():
            output_lines.append(f"\nAsset ID: {asset_id}")
            output_lines.append(f"Name: {info['name']}")
            output_lines.append(f"Type: {info['type']}")
            
            if info['usage']:
                output_lines.append("\nUsed in:")
                output_lines.append("-" * 60)
                output_lines.append(f"{'Campaign':<30} | {'Ad Group':<30}")
                output_lines.append("-" * 60)
                
                for usage in info['usage']:
                    campaign_str = f"{usage['campaign_name']} ({usage['campaign_id']})"
                    ad_group_str = f"{usage['ad_group_name']} ({usage['ad_group_id']})"
                    
                    output_lines.append(f"{campaign_str[:30]:<30} | {ad_group_str[:30]:<30}")
            
            output_lines.append("=" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving asset usage: {str(e)}"

@mcp.tool()
async def analyze_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)")
) -> str:
    """
    Analyze image assets with their performance metrics across campaigns.
    
    This comprehensive tool helps you understand which image assets are performing well
    by showing metrics like impressions, clicks, and conversions for each image.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_account_currency() to see what currency the account uses
    3. Finally run this command to analyze image asset performance
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Detailed report of image assets and their performance metrics
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    # Make sure to use a valid date range format
    # Valid formats are: LAST_7_DAYS, LAST_14_DAYS, LAST_30_DAYS, etc. (with underscores)
    if days == 7:
        date_range = "LAST_7_DAYS"
    elif days == 14:
        date_range = "LAST_14_DAYS"
    elif days == 30:
        date_range = "LAST_30_DAYS"
    else:
        # Default to 30 days if not a standard range
        date_range = "LAST_30_DAYS"
        
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.full_size.height_pixels,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.conversions,
            metrics.cost_micros
        FROM
            campaign_asset
        WHERE
            asset.type = 'IMAGE'
            AND segments.date DURING LAST_30_DAYS
        ORDER BY
            metrics.impressions DESC
        LIMIT 200
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error analyzing image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image asset performance data found for this customer ID and time period."
        
        # Group results by asset ID
        assets_data = {}
        for result in results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            
            if asset_id not in assets_data:
                assets_data[asset_id] = {
                    'name': asset.get('name', f"Asset {asset_id}"),
                    'url': asset.get('imageAsset', {}).get('fullSize', {}).get('url', 'N/A'),
                    'dimensions': f"{asset.get('imageAsset', {}).get('fullSize', {}).get('widthPixels', 'N/A')} x {asset.get('imageAsset', {}).get('fullSize', {}).get('heightPixels', 'N/A')}",
                    'impressions': 0,
                    'clicks': 0,
                    'conversions': 0,
                    'cost_micros': 0,
                    'campaigns': set(),
                    'ad_groups': set()
                }
            
            # Aggregate metrics
            metrics = result.get('metrics', {})
            assets_data[asset_id]['impressions'] += int(metrics.get('impressions', 0))
            assets_data[asset_id]['clicks'] += int(metrics.get('clicks', 0))
            assets_data[asset_id]['conversions'] += float(metrics.get('conversions', 0))
            assets_data[asset_id]['cost_micros'] += int(metrics.get('costMicros', 0))
            
            # Add campaign and ad group info
            campaign = result.get('campaign', {})
            ad_group = result.get('adGroup', {})
            
            if campaign.get('name'):
                assets_data[asset_id]['campaigns'].add(campaign.get('name'))
            if ad_group.get('name'):
                assets_data[asset_id]['ad_groups'].add(ad_group.get('name'))
        
        # Format the results
        output_lines = [f"Image Asset Performance Analysis for Customer ID {formatted_customer_id} (Last {days} days):"]
        output_lines.append("=" * 100)
        
        # Sort assets by impressions (highest first)
        sorted_assets = sorted(assets_data.items(), key=lambda x: x[1]['impressions'], reverse=True)
        
        for asset_id, data in sorted_assets:
            output_lines.append(f"\nAsset ID: {asset_id}")
            output_lines.append(f"Name: {data['name']}")
            output_lines.append(f"Dimensions: {data['dimensions']}")
            
            # Calculate CTR if there are impressions
            ctr = (data['clicks'] / data['impressions'] * 100) if data['impressions'] > 0 else 0
            
            # Format metrics
            output_lines.append(f"\nPerformance Metrics:")
            output_lines.append(f"  Impressions: {data['impressions']:,}")
            output_lines.append(f"  Clicks: {data['clicks']:,}")
            output_lines.append(f"  CTR: {ctr:.2f}%")
            output_lines.append(f"  Conversions: {data['conversions']:.2f}")
            output_lines.append(f"  Cost (micros): {data['cost_micros']:,}")
            
            # Show where it's used
            output_lines.append(f"\nUsed in {len(data['campaigns'])} campaigns:")
            for campaign in list(data['campaigns'])[:5]:  # Show first 5 campaigns
                output_lines.append(f"  - {campaign}")
            if len(data['campaigns']) > 5:
                output_lines.append(f"  - ... and {len(data['campaigns']) - 5} more")
            
            # Add URL
            if data['url'] != 'N/A':
                output_lines.append(f"\nImage URL: {data['url']}")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error analyzing image assets: {str(e)}"

@mcp.tool()
async def list_resources(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'")
) -> str:
    """
    List valid resources that can be used in GAQL FROM clauses.
    
    Args:
        customer_id: The Google Ads customer ID as a string
        
    Returns:
        Formatted list of valid resources
    """
    # Example query that lists some common resources
    # This might need to be adjusted based on what's available in your API version
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM
            google_ads_field
        WHERE
            google_ads_field.category = 'RESOURCE'
        ORDER BY
            google_ads_field.name
    """
    
    # Use your existing run_gaql function to execute this query
    return await run_gaql(customer_id, query)

# =============================================================================
# WRITE / MUTATE TOOLS
# =============================================================================

def _mutate(customer_id: str, resource_path: str, operations: list) -> dict:
    """Generic mutate helper for Google Ads API."""
    creds = get_credentials()
    headers = get_headers(creds)
    formatted_id = format_customer_id(customer_id)
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/{resource_path}:mutate"
    payload = {"operations": operations}
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 200:
        raise Exception(f"Mutate failed ({response.status_code}): {response.text}")
    return response.json()


@mcp.tool()
async def update_campaign_status(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    campaign_id: str = Field(description="The campaign ID to update"),
    status: str = Field(description="New status: 'ENABLED' or 'PAUSED'")
) -> str:
    """
    Enable or pause a campaign.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        campaign_id: The campaign ID to update
        status: New status - 'ENABLED' or 'PAUSED'

    Returns:
        Success or error message
    """
    status = status.upper()
    if status not in ("ENABLED", "PAUSED"):
        return "Error: status must be 'ENABLED' or 'PAUSED'"
    try:
        formatted_id = format_customer_id(customer_id)
        ops = [{
            "updateMask": "status",
            "update": {
                "resourceName": f"customers/{formatted_id}/campaigns/{campaign_id}",
                "status": status
            }
        }]
        result = _mutate(customer_id, "campaigns", ops)
        return f"Campaign {campaign_id} status updated to {status}. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error updating campaign status: {str(e)}"


@mcp.tool()
async def add_negative_keywords(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    campaign_id: str = Field(description="Campaign ID to add negative keywords to"),
    keywords: str = Field(description="Comma-separated list of negative keywords (e.g. 'near me, showroom, test drive')"),
    match_type: str = Field(default="BROAD", description="Match type: 'BROAD', 'PHRASE', or 'EXACT'")
) -> str:
    """
    Add negative keywords to a campaign to block irrelevant searches.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        campaign_id: Campaign ID to add negative keywords to
        keywords: Comma-separated list of negative keywords
        match_type: Match type - 'BROAD', 'PHRASE', or 'EXACT' (default: BROAD)

    Returns:
        Success or error message with list of added keywords
    """
    match_type = match_type.upper()
    if match_type not in ("BROAD", "PHRASE", "EXACT"):
        return "Error: match_type must be 'BROAD', 'PHRASE', or 'EXACT'"
    try:
        formatted_id = format_customer_id(customer_id)
        keyword_list = [kw.strip() for kw in keywords.split(",") if kw.strip()]
        ops = []
        for kw in keyword_list:
            ops.append({
                "create": {
                    "campaign": f"customers/{formatted_id}/campaigns/{campaign_id}",
                    "negative": True,
                    "keyword": {
                        "text": kw,
                        "matchType": match_type
                    }
                }
            })
        result = _mutate(customer_id, "campaignCriteria", ops)
        return f"Added {len(keyword_list)} negative keywords to campaign {campaign_id}: {keyword_list}\nResponse: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error adding negative keywords: {str(e)}"


@mcp.tool()
async def update_campaign_budget(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    campaign_id: str = Field(description="Campaign ID to update budget for"),
    budget_amount: float = Field(description="New daily budget amount in account currency (e.g. 50.0 for 50 AED)")
) -> str:
    """
    Update a campaign's daily budget.

    First finds the budget resource for the campaign, then updates it.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        campaign_id: Campaign ID to update budget for
        budget_amount: New daily budget in account currency (not micros)

    Returns:
        Success or error message
    """
    try:
        # First get the budget resource name for this campaign
        budget_query = f"""
            SELECT campaign.campaign_budget, campaign_budget.amount_micros
            FROM campaign
            WHERE campaign.id = {campaign_id}
            LIMIT 1
        """
        creds = get_credentials()
        headers = get_headers(creds)
        formatted_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/googleAds:search"
        resp = requests.post(url, headers=headers, json={"query": budget_query})
        if resp.status_code != 200:
            return f"Error finding campaign budget: {resp.text}"
        results = resp.json()
        if not results.get("results"):
            return f"Campaign {campaign_id} not found"

        budget_resource = results["results"][0].get("campaign", {}).get("campaignBudget", "")
        if not budget_resource:
            return "Could not find budget resource for this campaign"

        amount_micros = int(budget_amount * 1_000_000)
        ops = [{
            "updateMask": "amount_micros",
            "update": {
                "resourceName": budget_resource,
                "amountMicros": str(amount_micros)
            }
        }]
        result = _mutate(customer_id, "campaignBudgets", ops)
        return f"Budget for campaign {campaign_id} updated to {budget_amount} (was {int(results['results'][0].get('campaignBudget', {}).get('amountMicros', 0)) / 1_000_000:.2f}). Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error updating budget: {str(e)}"


@mcp.tool()
async def add_keywords_to_ad_group(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    ad_group_id: str = Field(description="Ad group ID to add keywords to"),
    keywords: str = Field(description="Comma-separated keywords (e.g. 'tesla parts, tesla model 3 parts')"),
    match_type: str = Field(default="BROAD", description="Match type: 'BROAD', 'PHRASE', or 'EXACT'")
) -> str:
    """
    Add keywords to an ad group.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        ad_group_id: Ad group ID to add keywords to
        keywords: Comma-separated list of keywords
        match_type: Match type - 'BROAD', 'PHRASE', or 'EXACT'

    Returns:
        Success or error message
    """
    match_type = match_type.upper()
    if match_type not in ("BROAD", "PHRASE", "EXACT"):
        return "Error: match_type must be 'BROAD', 'PHRASE', or 'EXACT'"
    try:
        formatted_id = format_customer_id(customer_id)
        keyword_list = [kw.strip() for kw in keywords.split(",") if kw.strip()]
        ops = []
        for kw in keyword_list:
            ops.append({
                "create": {
                    "adGroup": f"customers/{formatted_id}/adGroups/{ad_group_id}",
                    "keyword": {
                        "text": kw,
                        "matchType": match_type
                    },
                    "status": "ENABLED"
                }
            })
        result = _mutate(customer_id, "adGroupCriteria", ops)
        return f"Added {len(keyword_list)} keywords to ad group {ad_group_id}: {keyword_list}\nResponse: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error adding keywords: {str(e)}"


@mcp.tool()
async def remove_keyword_from_ad_group(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    ad_group_id: str = Field(description="Ad group ID the keyword belongs to"),
    criterion_id: str = Field(description="The criterion ID of the keyword to remove (get from keyword queries)")
) -> str:
    """
    Remove a keyword from an ad group.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        ad_group_id: Ad group ID the keyword belongs to
        criterion_id: Criterion ID of the keyword to remove

    Returns:
        Success or error message
    """
    try:
        formatted_id = format_customer_id(customer_id)
        ops = [{
            "remove": f"customers/{formatted_id}/adGroupCriteria/{ad_group_id}~{criterion_id}"
        }]
        result = _mutate(customer_id, "adGroupCriteria", ops)
        return f"Removed keyword criterion {criterion_id} from ad group {ad_group_id}. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error removing keyword: {str(e)}"


@mcp.tool()
async def create_ad_group(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    campaign_id: str = Field(description="Campaign ID to create the ad group in"),
    name: str = Field(description="Name for the new ad group"),
    cpc_bid_micros: int = Field(default=2000000, description="CPC bid in micros (default: 2000000 = 2.0 in account currency)")
) -> str:
    """
    Create a new ad group in a campaign.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        campaign_id: Campaign ID to create ad group in
        name: Name for the new ad group
        cpc_bid_micros: CPC bid in micros (default: 2000000)

    Returns:
        Success message with new ad group resource name
    """
    try:
        formatted_id = format_customer_id(customer_id)
        ops = [{
            "create": {
                "campaign": f"customers/{formatted_id}/campaigns/{campaign_id}",
                "name": name,
                "type": "SEARCH_STANDARD",
                "status": "ENABLED",
                "cpcBidMicros": str(cpc_bid_micros)
            }
        }]
        result = _mutate(customer_id, "adGroups", ops)
        return f"Created ad group '{name}' in campaign {campaign_id}. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error creating ad group: {str(e)}"


@mcp.tool()
async def create_responsive_search_ad(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    ad_group_id: str = Field(description="Ad group ID to create the ad in"),
    headlines: str = Field(description="Pipe-separated headlines (min 3, max 15). E.g. 'Tesla Parts Dubai|Genuine Tesla Parts|Free Delivery'"),
    descriptions: str = Field(description="Pipe-separated descriptions (min 2, max 4). E.g. 'Best prices on Tesla parts|Same day delivery in UAE'"),
    final_url: str = Field(description="The landing page URL for the ad")
) -> str:
    """
    Create a Responsive Search Ad (RSA) in an ad group.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        ad_group_id: Ad group ID to create the ad in
        headlines: Pipe-separated headlines (min 3, max 15)
        descriptions: Pipe-separated descriptions (min 2, max 4)
        final_url: Landing page URL

    Returns:
        Success message with new ad details
    """
    try:
        formatted_id = format_customer_id(customer_id)
        headline_list = [h.strip() for h in headlines.split("|") if h.strip()]
        desc_list = [d.strip() for d in descriptions.split("|") if d.strip()]

        if len(headline_list) < 3:
            return "Error: Need at least 3 headlines"
        if len(desc_list) < 2:
            return "Error: Need at least 2 descriptions"

        headline_assets = [{"text": h} for h in headline_list[:15]]
        desc_assets = [{"text": d} for d in desc_list[:4]]

        ops = [{
            "create": {
                "adGroup": f"customers/{formatted_id}/adGroups/{ad_group_id}",
                "ad": {
                    "responsiveSearchAd": {
                        "headlines": headline_assets,
                        "descriptions": desc_assets
                    },
                    "finalUrls": [final_url]
                },
                "status": "ENABLED"
            }
        }]
        result = _mutate(customer_id, "adGroupAds", ops)
        return f"Created RSA in ad group {ad_group_id} with {len(headline_list)} headlines, {len(desc_list)} descriptions. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error creating ad: {str(e)}"


@mcp.tool()
async def update_ad_group_status(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    ad_group_id: str = Field(description="Ad group ID to update"),
    status: str = Field(description="New status: 'ENABLED' or 'PAUSED'")
) -> str:
    """
    Enable or pause an ad group.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        ad_group_id: Ad group ID to update
        status: New status - 'ENABLED' or 'PAUSED'

    Returns:
        Success or error message
    """
    status = status.upper()
    if status not in ("ENABLED", "PAUSED"):
        return "Error: status must be 'ENABLED' or 'PAUSED'"
    try:
        formatted_id = format_customer_id(customer_id)
        ops = [{
            "updateMask": "status",
            "update": {
                "resourceName": f"customers/{formatted_id}/adGroups/{ad_group_id}",
                "status": status
            }
        }]
        result = _mutate(customer_id, "adGroups", ops)
        return f"Ad group {ad_group_id} status updated to {status}. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error updating ad group status: {str(e)}"


@mcp.tool()
async def update_ad_status(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    ad_group_id: str = Field(description="Ad group ID the ad belongs to"),
    ad_id: str = Field(description="Ad ID to update"),
    status: str = Field(description="New status: 'ENABLED' or 'PAUSED'")
) -> str:
    """
    Enable or pause an ad.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        ad_group_id: Ad group ID the ad belongs to
        ad_id: Ad ID to update
        status: New status - 'ENABLED' or 'PAUSED'

    Returns:
        Success or error message
    """
    status = status.upper()
    if status not in ("ENABLED", "PAUSED"):
        return "Error: status must be 'ENABLED' or 'PAUSED'"
    try:
        formatted_id = format_customer_id(customer_id)
        ops = [{
            "updateMask": "status",
            "update": {
                "resourceName": f"customers/{formatted_id}/adGroupAds/{ad_group_id}~{ad_id}",
                "status": status
            }
        }]
        result = _mutate(customer_id, "adGroupAds", ops)
        return f"Ad {ad_id} in ad group {ad_group_id} status updated to {status}. Response: {json.dumps(result, indent=2)}"
    except Exception as e:
        return f"Error updating ad status: {str(e)}"


@mcp.tool()
async def generic_mutate(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    resource_type: str = Field(description="Resource type (e.g. 'campaigns', 'adGroups', 'adGroupCriteria', 'campaignCriteria', 'assets', 'campaignAssets')"),
    operations_json: str = Field(description="JSON string of operations array. Each operation should have 'create', 'update' (with 'updateMask'), or 'remove' key.")
) -> str:
    """
    Execute a generic mutate operation on any Google Ads resource.

    This is the most flexible write tool — use it for any operation not covered
    by the specialized tools above.

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        resource_type: The resource endpoint (e.g. 'campaigns', 'adGroups', 'campaignCriteria')
        operations_json: JSON string of the operations array

    Returns:
        API response or error message

    Example operations_json for enabling a campaign:
        '[{"updateMask": "status", "update": {"resourceName": "customers/1234567890/campaigns/123", "status": "ENABLED"}}]'
    """
    try:
        ops = json.loads(operations_json)
        if not isinstance(ops, list):
            return "Error: operations_json must be a JSON array"
        result = _mutate(customer_id, resource_type, ops)
        return f"Mutate on {resource_type} succeeded. Response: {json.dumps(result, indent=2)}"
    except json.JSONDecodeError as e:
        return f"Error parsing operations JSON: {str(e)}"
    except Exception as e:
        return f"Error executing mutate: {str(e)}"


# =============================================================================
# SNAPSHOT & CHANGELOG TOOLS
# =============================================================================

SNAPSHOTS_DIR = Path("/home/talas9/talas-ads/snapshots")
CHANGELOG_PATH = Path("/home/talas9/talas-ads/changelog.jsonl")

# Ensure snapshots directory exists
SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def _gaql_search(customer_id: str, query: str) -> list:
    """Execute a GAQL query and return raw result rows (list of dicts).

    Handles credentials, headers, pagination via nextPageToken, and error raising
    so callers get a simple list back.
    """
    creds = get_credentials()
    headers = get_headers(creds)
    formatted_id = format_customer_id(customer_id)
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/googleAds:search"

    all_results = []
    payload = {"query": query}

    while True:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            raise Exception(f"GAQL query failed ({response.status_code}): {response.text}")
        data = response.json()
        all_results.extend(data.get("results", []))
        next_token = data.get("nextPageToken")
        if not next_token:
            break
        payload["pageToken"] = next_token

    return all_results


@mcp.tool()
async def create_snapshot(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '3552856345'"),
    description: str = Field(default="manual", description="Short description for the snapshot (used in filename, e.g. 'before_pause_campaign')")
) -> str:
    """
    Capture the full account state and save it as a JSON snapshot.

    Captures:
    - All campaigns (id, name, status, budget, bidding strategy, channel type, geo targets)
    - All ad groups (id, name, status, campaign, cpc bid)
    - All keywords (ad group, text, match type, status, criterion id)
    - All negative keywords (campaign level)
    - All ads (id, status, ad group, headlines, descriptions, final urls)

    The snapshot is saved to /home/talas9/talas-ads/snapshots/{timestamp}_{description}.json

    Args:
        customer_id: Google Ads customer ID (10 digits, no dashes)
        description: Short description for the snapshot filename

    Returns:
        The snapshot filename and a summary of captured entities
    """
    try:
        formatted_id = format_customer_id(customer_id)
        snapshot = {
            "metadata": {
                "customer_id": formatted_id,
                "description": description,
                "captured_at": datetime.utcnow().isoformat() + "Z",
            },
            "campaigns": [],
            "ad_groups": [],
            "keywords": [],
            "negative_keywords": [],
            "ads": [],
        }

        # --- Campaigns -----------------------------------------------------------
        campaign_query = """
            SELECT
                campaign.id,
                campaign.name,
                campaign.status,
                campaign.campaign_budget,
                campaign.bidding_strategy_type,
                campaign.advertising_channel_type
            FROM campaign
            WHERE campaign.status != 'REMOVED'
        """
        campaign_rows = _gaql_search(customer_id, campaign_query)
        for row in campaign_rows:
            c = row.get("campaign", {})
            snapshot["campaigns"].append({
                "id": c.get("id"),
                "name": c.get("name"),
                "status": c.get("status"),
                "budget": c.get("campaignBudget"),
                "bidding_strategy_type": c.get("biddingStrategyType"),
                "channel_type": c.get("advertisingChannelType"),
            })

        # --- Geo targets per campaign --------------------------------------------
        geo_query = """
            SELECT
                campaign.id,
                campaign_criterion.location.geo_target_constant,
                campaign_criterion.negative
            FROM campaign_criterion
            WHERE campaign_criterion.type = 'LOCATION'
        """
        try:
            geo_rows = _gaql_search(customer_id, geo_query)
            # Build a map campaign_id -> list of geo targets
            geo_map: Dict[str, list] = {}
            for row in geo_rows:
                cid = row.get("campaign", {}).get("id")
                criterion = row.get("campaignCriterion", {})
                geo_entry = {
                    "geo_target_constant": criterion.get("location", {}).get("geoTargetConstant"),
                    "negative": criterion.get("negative", False),
                }
                geo_map.setdefault(cid, []).append(geo_entry)
            # Attach geo targets to campaigns
            for camp in snapshot["campaigns"]:
                camp["geo_targets"] = geo_map.get(camp["id"], [])
        except Exception as e:
            logger.warning(f"Could not fetch geo targets: {e}")
            for camp in snapshot["campaigns"]:
                camp["geo_targets"] = []

        # --- Ad Groups -----------------------------------------------------------
        ag_query = """
            SELECT
                ad_group.id,
                ad_group.name,
                ad_group.status,
                ad_group.cpc_bid_micros,
                campaign.id,
                campaign.name
            FROM ad_group
            WHERE ad_group.status != 'REMOVED'
        """
        ag_rows = _gaql_search(customer_id, ag_query)
        for row in ag_rows:
            ag = row.get("adGroup", {})
            c = row.get("campaign", {})
            snapshot["ad_groups"].append({
                "id": ag.get("id"),
                "name": ag.get("name"),
                "status": ag.get("status"),
                "cpc_bid_micros": ag.get("cpcBidMicros"),
                "campaign_id": c.get("id"),
                "campaign_name": c.get("name"),
            })

        # --- Keywords (ad group level) -------------------------------------------
        kw_query = """
            SELECT
                ad_group.id,
                ad_group.name,
                ad_group_criterion.criterion_id,
                ad_group_criterion.keyword.text,
                ad_group_criterion.keyword.match_type,
                ad_group_criterion.status,
                ad_group_criterion.negative
            FROM ad_group_criterion
            WHERE ad_group_criterion.type = 'KEYWORD'
              AND ad_group_criterion.status != 'REMOVED'
        """
        kw_rows = _gaql_search(customer_id, kw_query)
        for row in kw_rows:
            ag = row.get("adGroup", {})
            crit = row.get("adGroupCriterion", {})
            kw = crit.get("keyword", {})
            snapshot["keywords"].append({
                "ad_group_id": ag.get("id"),
                "ad_group_name": ag.get("name"),
                "criterion_id": crit.get("criterionId"),
                "text": kw.get("text"),
                "match_type": kw.get("matchType"),
                "status": crit.get("status"),
                "negative": crit.get("negative", False),
            })

        # --- Negative Keywords (campaign level) ----------------------------------
        neg_query = """
            SELECT
                campaign.id,
                campaign.name,
                campaign_criterion.criterion_id,
                campaign_criterion.keyword.text,
                campaign_criterion.keyword.match_type,
                campaign_criterion.negative
            FROM campaign_criterion
            WHERE campaign_criterion.type = 'KEYWORD'
              AND campaign_criterion.negative = TRUE
        """
        try:
            neg_rows = _gaql_search(customer_id, neg_query)
            for row in neg_rows:
                c = row.get("campaign", {})
                crit = row.get("campaignCriterion", {})
                kw = crit.get("keyword", {})
                snapshot["negative_keywords"].append({
                    "campaign_id": c.get("id"),
                    "campaign_name": c.get("name"),
                    "criterion_id": crit.get("criterionId"),
                    "text": kw.get("text"),
                    "match_type": kw.get("matchType"),
                })
        except Exception as e:
            logger.warning(f"Could not fetch campaign negative keywords: {e}")

        # --- Ads -----------------------------------------------------------------
        ads_query = """
            SELECT
                ad_group_ad.ad.id,
                ad_group_ad.status,
                ad_group_ad.ad.type,
                ad_group_ad.ad.final_urls,
                ad_group_ad.ad.responsive_search_ad.headlines,
                ad_group_ad.ad.responsive_search_ad.descriptions,
                ad_group.id,
                ad_group.name,
                campaign.id,
                campaign.name
            FROM ad_group_ad
            WHERE ad_group_ad.status != 'REMOVED'
        """
        ads_rows = _gaql_search(customer_id, ads_query)
        for row in ads_rows:
            ad_data = row.get("adGroupAd", {})
            ad = ad_data.get("ad", {})
            ag = row.get("adGroup", {})
            c = row.get("campaign", {})
            rsa = ad.get("responsiveSearchAd", {})
            snapshot["ads"].append({
                "id": ad.get("id"),
                "status": ad_data.get("status"),
                "type": ad.get("type"),
                "final_urls": ad.get("finalUrls", []),
                "headlines": [h.get("text") for h in rsa.get("headlines", [])] if rsa else [],
                "descriptions": [d.get("text") for d in rsa.get("descriptions", [])] if rsa else [],
                "ad_group_id": ag.get("id"),
                "ad_group_name": ag.get("name"),
                "campaign_id": c.get("id"),
                "campaign_name": c.get("name"),
            })

        # --- Save snapshot -------------------------------------------------------
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_desc = ''.join(c if c.isalnum() or c in '-_' else '_' for c in description)
        filename = f"{ts}_{safe_desc}.json"
        filepath = SNAPSHOTS_DIR / filename

        with open(filepath, "w") as f:
            json.dump(snapshot, f, indent=2, default=str)

        summary = (
            f"Snapshot saved: {filename}\n"
            f"  Campaigns: {len(snapshot['campaigns'])}\n"
            f"  Ad Groups: {len(snapshot['ad_groups'])}\n"
            f"  Keywords: {len(snapshot['keywords'])}\n"
            f"  Negative Keywords: {len(snapshot['negative_keywords'])}\n"
            f"  Ads: {len(snapshot['ads'])}"
        )
        return summary

    except Exception as e:
        return f"Error creating snapshot: {str(e)}"


@mcp.tool()
async def list_snapshots() -> str:
    """
    List all saved account snapshots with timestamps and descriptions.

    Returns:
        Formatted list of snapshot files with their metadata
    """
    try:
        SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(SNAPSHOTS_DIR.glob("*.json"), reverse=True)

        if not files:
            return "No snapshots found."

        lines = ["Saved Snapshots:", "=" * 70]
        for f in files:
            # Try to read metadata from the file
            try:
                with open(f, "r") as fh:
                    data = json.load(fh)
                meta = data.get("metadata", {})
                captured = meta.get("captured_at", "unknown")
                desc = meta.get("description", "N/A")
                cid = meta.get("customer_id", "N/A")
                counts = (
                    f"campaigns={len(data.get('campaigns', []))}, "
                    f"ad_groups={len(data.get('ad_groups', []))}, "
                    f"keywords={len(data.get('keywords', []))}, "
                    f"neg_kw={len(data.get('negative_keywords', []))}, "
                    f"ads={len(data.get('ads', []))}"
                )
            except Exception:
                captured = "error reading"
                desc = "error"
                cid = "N/A"
                counts = "N/A"

            lines.append(f"\n  File: {f.name}")
            lines.append(f"  Captured: {captured}")
            lines.append(f"  Account: {cid}")
            lines.append(f"  Description: {desc}")
            lines.append(f"  Contents: {counts}")
            lines.append("-" * 70)

        return "\n".join(lines)

    except Exception as e:
        return f"Error listing snapshots: {str(e)}"


@mcp.tool()
async def get_snapshot(
    filename: str = Field(description="The snapshot filename (e.g. '20260211_143022_before_pause.json')")
) -> str:
    """
    Read and return the contents of a specific snapshot file.

    Args:
        filename: The snapshot filename to read

    Returns:
        The full JSON contents of the snapshot
    """
    try:
        filepath = SNAPSHOTS_DIR / filename

        if not filepath.exists():
            # Try to find a partial match
            matches = list(SNAPSHOTS_DIR.glob(f"*{filename}*"))
            if matches:
                filepath = matches[0]
            else:
                available = [f.name for f in SNAPSHOTS_DIR.glob("*.json")]
                return f"Snapshot '{filename}' not found. Available snapshots: {available}"

        with open(filepath, "r") as f:
            data = json.load(f)

        return json.dumps(data, indent=2, default=str)

    except Exception as e:
        return f"Error reading snapshot: {str(e)}"


@mcp.tool()
async def log_change(
    action: str = Field(description="What was done (e.g. 'pause_campaign', 'add_negative_keywords', 'update_geo_targeting')"),
    details: str = Field(description="Specifics of the change — campaign name, keywords added, old/new values, etc."),
    reason: str = Field(description="Why the change was made"),
    snapshot_before: str = Field(default="", description="Reference to snapshot file taken before the change (filename, optional)"),
    agent: str = Field(default="google-ads-analyst", description="Which agent made the change")
) -> str:
    """
    Log a change entry to the append-only changelog (JSONL format).

    Each entry is a single JSON line in /home/talas9/talas-ads/changelog.jsonl containing:
    - timestamp (ISO format)
    - action
    - details
    - reason
    - snapshot_before
    - agent

    Args:
        action: What was done
        details: Specifics of the change
        reason: Why the change was made
        snapshot_before: Reference to snapshot file taken before the change
        agent: Which agent made the change

    Returns:
        Confirmation that the entry was logged
    """
    try:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "details": details,
            "reason": reason,
            "snapshot_before": snapshot_before,
            "agent": agent,
        }

        # Append to changelog (JSONL — one JSON object per line)
        with open(CHANGELOG_PATH, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        return f"Change logged: [{entry['timestamp']}] {action} by {agent}"

    except Exception as e:
        return f"Error logging change: {str(e)}"


@mcp.tool()
async def get_changelog(
    date_from: str = Field(default="", description="Start date filter (ISO format, e.g. '2026-01-01'). Leave empty for no lower bound."),
    date_to: str = Field(default="", description="End date filter (ISO format, e.g. '2026-02-11'). Leave empty for no upper bound."),
    action_filter: str = Field(default="", description="Filter by action type (e.g. 'pause_campaign'). Leave empty for all actions."),
    limit: int = Field(default=50, description="Maximum number of entries to return (most recent first)")
) -> str:
    """
    Return changelog entries, optionally filtered by date range or action type.

    Args:
        date_from: Start date filter (ISO format). Leave empty for no lower bound.
        date_to: End date filter (ISO format). Leave empty for no upper bound.
        action_filter: Filter by action type. Leave empty for all actions.
        limit: Maximum number of entries to return (most recent first, default 50)

    Returns:
        Formatted changelog entries
    """
    try:
        if not CHANGELOG_PATH.exists():
            return "No changelog found. No changes have been logged yet."

        entries = []
        with open(CHANGELOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

        if not entries:
            return "Changelog is empty."

        # Apply filters
        if date_from:
            entries = [e for e in entries if e.get("timestamp", "") >= date_from]
        if date_to:
            # Add a day boundary so "2026-02-11" includes the whole day
            to_bound = date_to + "T23:59:59Z" if "T" not in date_to else date_to
            entries = [e for e in entries if e.get("timestamp", "") <= to_bound]
        if action_filter:
            entries = [e for e in entries if e.get("action", "") == action_filter]

        # Most recent first, apply limit
        entries = list(reversed(entries))[:limit]

        if not entries:
            return "No changelog entries match the given filters."

        lines = [f"Changelog ({len(entries)} entries):", "=" * 80]
        for e in entries:
            lines.append(f"\n  Timestamp: {e.get('timestamp', 'N/A')}")
            lines.append(f"  Action: {e.get('action', 'N/A')}")
            lines.append(f"  Details: {e.get('details', 'N/A')}")
            lines.append(f"  Reason: {e.get('reason', 'N/A')}")
            lines.append(f"  Snapshot Before: {e.get('snapshot_before', 'N/A') or 'none'}")
            lines.append(f"  Agent: {e.get('agent', 'N/A')}")
            lines.append("-" * 80)

        return "\n".join(lines)

    except Exception as e:
        return f"Error reading changelog: {str(e)}"


# =============================================================================
# GOOGLE BUSINESS PROFILE TOOLS
# =============================================================================

GBP_ACCOUNT_MGMT_BASE = "https://mybusinessaccountmanagement.googleapis.com/v1"
GBP_BUSINESS_INFO_BASE = "https://mybusinessbusinessinformation.googleapis.com/v1"

def _gbp_headers():
    """Get headers for Google Business Profile API requests."""
    creds = get_credentials()
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            raise ValueError("GBP credentials are invalid")
    return {
        'Authorization': f'Bearer {creds.token}',
        'content-type': 'application/json'
    }


@mcp.tool()
async def list_gbp_accounts() -> str:
    """
    List all Google Business Profile accounts accessible with current credentials.

    Returns:
        Formatted list of GBP accounts with their IDs and names
    """
    try:
        headers = _gbp_headers()
        url = f"{GBP_ACCOUNT_MGMT_BASE}/accounts"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return f"Error listing GBP accounts: {response.text}"
        data = response.json()
        accounts = data.get('accounts', [])
        if not accounts:
            return "No Google Business Profile accounts found."
        lines = ["Google Business Profile Accounts:", "=" * 60]
        for acc in accounts:
            lines.append(f"  Name: {acc.get('name', 'N/A')}")
            lines.append(f"  Account Name: {acc.get('accountName', 'N/A')}")
            lines.append(f"  Type: {acc.get('type', 'N/A')}")
            lines.append(f"  Role: {acc.get('role', 'N/A')}")
            lines.append(f"  Verification State: {acc.get('verificationState', 'N/A')}")
            lines.append("-" * 60)
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing GBP accounts: {str(e)}"


@mcp.tool()
async def list_gbp_locations(
    account_id: str = Field(description="GBP account ID (from list_gbp_accounts, e.g. 'accounts/123456789'). Pass just the number or the full path."),
    read_mask: str = Field(default="name,title,storefrontAddress,phoneNumbers,websiteUri,regularHours,storeCode,labels", description="Comma-separated fields to return")
) -> str:
    """
    List all business locations in a Google Business Profile account.

    Args:
        account_id: The GBP account ID
        read_mask: Fields to include in the response

    Returns:
        Formatted list of locations with address, phone, hours, etc.
    """
    try:
        headers = _gbp_headers()
        acct = account_id if account_id.startswith("accounts/") else f"accounts/{account_id}"
        url = f"{GBP_BUSINESS_INFO_BASE}/{acct}/locations?readMask={read_mask}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return f"Error listing locations: {response.text}"
        data = response.json()
        locations = data.get('locations', [])
        if not locations:
            return "No locations found for this account."
        lines = [f"Locations for {acct}:", "=" * 80]
        for loc in locations:
            lines.append(f"\n  Resource: {loc.get('name', 'N/A')}")
            lines.append(f"  Title: {loc.get('title', 'N/A')}")
            lines.append(f"  Store Code: {loc.get('storeCode', 'N/A')}")
            lines.append(f"  Labels: {', '.join(loc.get('labels', [])) or 'None'}")
            addr = loc.get('storefrontAddress', {})
            if addr:
                addr_lines = addr.get('addressLines', [])
                lines.append(f"  Address: {', '.join(addr_lines)}")
                lines.append(f"  City: {addr.get('locality', 'N/A')}")
                lines.append(f"  Region: {addr.get('administrativeArea', 'N/A')}")
                lines.append(f"  Country: {addr.get('regionCode', 'N/A')}")
                lines.append(f"  Postal Code: {addr.get('postalCode', 'N/A')}")
            phone = loc.get('phoneNumbers', {})
            if phone:
                lines.append(f"  Primary Phone: {phone.get('primaryPhone', 'N/A')}")
                additional = phone.get('additionalPhones', [])
                if additional:
                    lines.append(f"  Additional Phones: {', '.join(additional)}")
            lines.append(f"  Website: {loc.get('websiteUri', 'N/A')}")
            hours = loc.get('regularHours', {})
            if hours and hours.get('periods'):
                lines.append("  Hours:")
                for period in hours['periods']:
                    open_day = period.get('openDay', '')
                    open_time = period.get('openTime', {})
                    close_day = period.get('closeDay', '')
                    close_time = period.get('closeTime', {})
                    oh = f"{open_time.get('hours', 0):02d}:{open_time.get('minutes', 0):02d}"
                    ch = f"{close_time.get('hours', 0):02d}:{close_time.get('minutes', 0):02d}"
                    lines.append(f"    {open_day}: {oh} - {ch}")
            lines.append("-" * 80)
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing locations: {str(e)}"


@mcp.tool()
async def get_gbp_location(
    location_name: str = Field(description="Full location resource name (e.g. 'locations/123456789')"),
    read_mask: str = Field(default="name,title,storefrontAddress,phoneNumbers,websiteUri,regularHours,storeCode,labels,metadata,profile,serviceArea", description="Comma-separated fields to return")
) -> str:
    """
    Get detailed information about a specific business location.

    Args:
        location_name: The full location resource name
        read_mask: Fields to include in the response

    Returns:
        Detailed location information
    """
    try:
        headers = _gbp_headers()
        loc = location_name if location_name.startswith("locations/") else f"locations/{location_name}"
        url = f"{GBP_BUSINESS_INFO_BASE}/{loc}?readMask={read_mask}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return f"Error getting location: {response.text}"
        return json.dumps(response.json(), indent=2)
    except Exception as e:
        return f"Error getting location: {str(e)}"


@mcp.tool()
async def update_gbp_location(
    location_name: str = Field(description="Full location resource name (e.g. 'locations/123456789')"),
    update_mask: str = Field(description="Comma-separated fields to update (e.g. 'title,phoneNumbers,regularHours')"),
    update_body: str = Field(description="JSON string of the fields to update")
) -> str:
    """
    Update a business location's information (address, hours, phone, etc.).

    Args:
        location_name: The full location resource name
        update_mask: Which fields to update
        update_body: JSON string with the updated field values

    Returns:
        Updated location data or error message
    """
    try:
        headers = _gbp_headers()
        loc = location_name if location_name.startswith("locations/") else f"locations/{location_name}"
        url = f"{GBP_BUSINESS_INFO_BASE}/{loc}?updateMask={update_mask}"
        body = json.loads(update_body)
        response = requests.patch(url, headers=headers, json=body)
        if response.status_code != 200:
            return f"Error updating location: {response.text}"
        return f"Location updated successfully. Response: {json.dumps(response.json(), indent=2)}"
    except json.JSONDecodeError as e:
        return f"Error parsing update body JSON: {str(e)}"
    except Exception as e:
        return f"Error updating location: {str(e)}"


if __name__ == "__main__":
    # Start the MCP server on stdio transport
    mcp.run(transport="stdio")

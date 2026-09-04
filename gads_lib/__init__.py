"""Internal library for the gads CLI."""

__version__ = "3.10.0"

from .config import (
    PROJECT_ROOT,
    CONFIG_HOME,
    GLOBAL_HOME,
    SCOPE_ROOT,
    SCOPE_TYPE,
    DB_PATH,
    CREDS_PATH,
    SNAPSHOTS_DIR,
    DEV_TOKEN,
    LOGIN_CUSTOMER_ID,
    CUSTOMER_ID,
    API_VERSION,
    MERCHANT_CENTER_ID,
    GA4_PROPERTY_ID,
    TZ_NAME,
    CURRENCY,
)
from .auth import get_credentials
from .ads import (
    run_gaql,
    ads_search,
    ads_mutate,
    ads_batch_mutate,
    ads_upload_click_conversions,
    parse_partial_failure,
    extract_target_cpa,
    extract_target_roas,
    generate_keyword_ideas,
    generate_keyword_forecast,
    sanitize_keyword,
    audience_find_list,
    audience_create_list,
    audience_upload_csv,
)
from .db import get_db
from .gbp import (
    gbp_delete_reply,
    gbp_get_location,
    gbp_list_accounts,
    gbp_list_locations,
    gbp_list_reviews,
    gbp_reply_review,
    gbp_daily_metrics,
    gbp_multi_daily_metrics,
    gbp_search_keywords_monthly,
    gbp_batch_get_reviews,
    gbp_list_local_posts,
    gbp_create_local_post,
    gbp_delete_local_post,
    DAILY_METRICS,
)
from .merchant import (
    mc_get_account,
    mc_get_account_status,
    mc_get_return_policy,
    mc_get_shipping,
    mc_list_datafeeds,
    mc_list_product_statuses,
    mc_list_products,
    mc_register_gcp,
)
from .ga4 import (
    ga4_get_metadata,
    ga4_run_realtime_report,
    ga4_run_report,
    ga4_batch_run_reports,
    ga4_run_pivot_report,
    ga4_check_compatibility,
    list_key_events,
    create_key_event,
    delete_key_event,
    VALID_COUNTING_METHODS,
)
from .output import flatten, print_json, print_table, print_error, EXIT_CODES
from .timeutil import now_local, today_local

# AUTH User queries - loaded from SQL files
from app.database.queries import QUERIES

fetch_user = QUERIES["auth_fetch_user"]
fetch_user_policy = QUERIES["auth_fetch_user_policy"]
fetch_user_with_policy = QUERIES["auth_fetch_user_with_policy"]
fetch_user_condition = QUERIES["auth_fetch_user_condition"]
check_modified = QUERIES["auth_check_modified"]
fetch_user_with_policy_for_refresh = QUERIES["auth_fetch_user_with_policy_for_refresh"]
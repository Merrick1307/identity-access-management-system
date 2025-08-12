fetch_user = """SELECT * FROM users WHERE email = $1 AND tenant_id = $2"""

fetch_user_policy = """SELECT * FROM user_policies WHERE email = $1 AND tenant_id = $2"""

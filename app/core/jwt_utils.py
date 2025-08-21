import time

import jwt


async def create_jwt_token(payload: dict, secret_key: str):
    user_id = payload['user_id']
    headers = {
        "jti": f"{user_id}-{time.time_ns()}",
    }
    jwt_token = jwt.encode(
        payload, secret_key, algorithm=['HS256'], headers=headers
    )
    return jwt_token
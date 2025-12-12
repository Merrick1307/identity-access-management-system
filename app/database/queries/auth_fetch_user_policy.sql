SELECT policy_id, policy FROM user_policies 
WHERE user_id = $1 
AND tenant_id = $2
AND (
    (policy -> 'conditions' ->> 'validity_time')::timestamptz >= NOW() 
    OR NOT (policy -> 'conditions' ? 'validity_time')
)

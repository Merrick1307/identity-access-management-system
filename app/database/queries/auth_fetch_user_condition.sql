SELECT (policy -> 'condition') - 'validity_time' as condition
FROM user_policies 
WHERE user_id = $1 AND tenant_id = $2 AND policy ->> 'resource' = $3

INSERT INTO audit_logs 
(timestamp, level, logger_name, message, module, function, 
 line_number, thread_id, process_id, extra_data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)

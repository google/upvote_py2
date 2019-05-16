  ---------- device_names.sql ----------
  -- SCHEMA:
  -- device_id (STRING)
  -- hostname (STRING)
SELECT
  device_id,
  ARRAY_AGG(hostname IGNORE NULLS
  ORDER BY
    timestamp DESC
  LIMIT
    1) AS hostname
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`
GROUP BY
  device_id

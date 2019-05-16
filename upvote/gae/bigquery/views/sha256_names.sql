  ---------- sha256_names.sql ----------
  -- SCHEMA:
  -- sha256 (STRING)
  -- name (STRING)
SELECT
  sha256,
  ARRAY_AGG(name
  ORDER BY
    name
  LIMIT
    1)[
OFFSET
  (0)] name
FROM (
  SELECT
    DISTINCT sha256,
    first_seen_file_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Binary`
  WHERE
    first_seen_file_name IS NOT NULL
  UNION DISTINCT
  SELECT
    DISTINCT bundle_hash AS sha256,
    bundle_id AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Bundle`
  WHERE
    bundle_id IS NOT NULL
  UNION DISTINCT
  SELECT
    DISTINCT fingerprint AS sha256,
    common_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Certificate`
  WHERE
    common_name IS NOT NULL
  UNION DISTINCT
  SELECT
    DISTINCT sha256,
    file_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.BundleBinary`
  WHERE
    file_name IS NOT NULL
  UNION DISTINCT
  SELECT
    DISTINCT sha256,
    file_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution`
  WHERE
    file_name IS NOT NULL )
GROUP BY
  sha256

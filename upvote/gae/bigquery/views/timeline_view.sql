  ---------- timeline_view.sql ----------
  -- SCHEMA:
  -- timestamp (TIMESTAMP)
  -- detail (STRING)
  -- sha256 (STRING)
  -- device_id (STRING)
  -- username (STRING)
  ---------- All Binary rows ----------
SELECT
  b.timestamp,
  (CASE b.action
      WHEN 'FIRST_SEEN' THEN FORMAT('%s binary "%s" was first seen', b.platform, IFNULL(n.name,  SUBSTR(b.sha256, 0, 8)))
      WHEN 'SCORE_CHANGE' THEN FORMAT('%s binary "%s" changed score to %d', b.platform, IFNULL(n.name,
        SUBSTR(b.sha256, 0, 8)), b.score)
      WHEN 'STATE_CHANGE' THEN FORMAT('%s binary "%s" changed state to %s', b.platform, IFNULL(n.name,  SUBSTR(b.sha256, 0, 8)), b.state)
      WHEN 'RESET' THEN FORMAT('%s binary "%s" was reset', b.platform, IFNULL(n.name,
        SUBSTR(b.sha256, 0, 8)))
      WHEN 'COMMENT' THEN FORMAT('Comment on %s binary "%s": "%s"', b.platform, IFNULL(n.name,  SUBSTR(b.sha256, 0, 8)), b.comment)
      WHEN 'UPLOADED' THEN FORMAT('%s binary "%s" was uploaded', b.platform, IFNULL(n.name,
        SUBSTR(b.sha256, 0, 8)))
      ELSE '(unknown action)' END) AS detail,
  b.sha256,
  CAST(NULL AS string) AS device_id,
  CAST(NULL AS string) AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Binary` AS b
LEFT JOIN (
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
      file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution`
    WHERE
      file_name IS NOT NULL
    UNION DISTINCT
    SELECT
      DISTINCT sha256,
      first_seen_file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Binary`
    WHERE
      first_seen_file_name IS NOT NULL)
  GROUP BY
    sha256) AS n
ON
  b.sha256 = n.sha256
UNION ALL
  ---------- All Bundle rows ----------
SELECT
  b.timestamp,
  (CASE b.action
      WHEN 'FIRST_SEEN' THEN FORMAT('macOS bundle "%s" was first seen', IFNULL(b.bundle_id,  SUBSTR(b.bundle_hash, 0, 8)))
      WHEN 'SCORE_CHANGE' THEN FORMAT('macOS bundle "%s" changed score to %d', IFNULL(b.bundle_id,
        SUBSTR(b.bundle_hash, 0, 8)), b.score)
      WHEN 'STATE_CHANGE' THEN FORMAT('macOS bundle "%s" changed state to %s', IFNULL(b.bundle_id,  SUBSTR(b.bundle_hash, 0, 8)), b.state)
      WHEN 'RESET' THEN FORMAT('macOS bundle "%s" was reset', IFNULL(b.bundle_id,
        SUBSTR(b.bundle_hash, 0, 8)))
      WHEN 'COMMENT' THEN FORMAT('Comment on macOS bundle "%s": "%s"', IFNULL(b.bundle_id,  SUBSTR(b.bundle_hash, 0, 8)), b.comment)
      WHEN 'UPLOADED' THEN FORMAT('macOS bundle "%s" was uploaded', IFNULL(b.bundle_id,
        SUBSTR(b.bundle_hash, 0, 8)))
      ELSE '(unknown action)' END) AS detail,
  b.bundle_hash AS sha256,
  CAST(NULL AS string) AS device_id,
  CAST(NULL AS string) AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Bundle` AS b
UNION ALL
  ---------- All BundleBinary rows ----------
SELECT
  bb.timestamp,
  (CASE bb.action
      WHEN 'FIRST_SEEN' THEN FORMAT('macOS binary "%s" was first seen', IFNULL(bb.file_name,  SUBSTR(bb.sha256, 0, 8)))
      WHEN 'SCORE_CHANGE' THEN FORMAT('macOS binary "%s" changed score', IFNULL(bb.file_name,
        SUBSTR(bb.sha256, 0, 8)))
      WHEN 'STATE_CHANGE' THEN FORMAT('macOS binary "%s" changed state', IFNULL(bb.file_name,  SUBSTR(bb.sha256, 0, 8)))
      WHEN 'RESET' THEN FORMAT('macOS binary "%s" was reset', IFNULL(bb.file_name,
        SUBSTR(bb.sha256, 0, 8)))
      WHEN 'COMMENT' THEN FORMAT('Comment on macOS binary "%s"', IFNULL(bb.file_name,  SUBSTR(bb.sha256, 0, 8)))
      WHEN 'UPLOADED' THEN FORMAT('macOS binary "%s" was uploaded', IFNULL(bb.file_name,
        SUBSTR(bb.sha256, 0, 8)))
      ELSE '(unknown action)' END) AS detail,
  bb.sha256,
  CAST(NULL AS string) AS device_id,
  CAST(NULL AS string) AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.BundleBinary` AS bb
UNION ALL
  ---------- All Certificate rows ----------
SELECT
  c.timestamp,
  (CASE c.action
      WHEN 'FIRST_SEEN' THEN FORMAT('Certificate "%s" was first seen', IFNULL(c.common_name,  SUBSTR(c.fingerprint, 0, 8)))
      WHEN 'SCORE_CHANGE' THEN FORMAT('Certificate "%s" changed score to %d', IFNULL(c.common_name,
        SUBSTR(c.fingerprint, 0, 8)), c.score)
      WHEN 'STATE_CHANGE' THEN FORMAT('Certificate "%s" changed state to %s', IFNULL(c.common_name,  SUBSTR(c.fingerprint, 0, 8)), c.state)
      WHEN 'RESET' THEN FORMAT('Certificate "%s" was reset', IFNULL(c.common_name,
        SUBSTR(c.fingerprint, 0, 8)))
      WHEN 'COMMENT' THEN FORMAT('Comment on certificate "%s": "%s"', IFNULL(c.common_name,  SUBSTR(c.fingerprint, 0, 8)), c.comment)
      WHEN 'UPLOADED' THEN FORMAT('Certificate "%s" was uploaded', IFNULL(c.common_name,
        SUBSTR(c.fingerprint, 0, 8)))
      ELSE '(unknown action)' END) AS detail,
  c.fingerprint AS sha256,
  CAST(NULL AS string) AS device_id,
  CAST(NULL AS string) AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Certificate` AS c
UNION ALL
  ---------- Executions performed, where, and by whom ----------
SELECT
  DISTINCT e.timestamp,
  FORMAT('%s executed "%s" on %s device %s (%s)', e.executing_user, IFNULL(e.file_name,
      SUBSTR(e.sha256, 0, 8)), e.platform, IFNULL(h.hostname,
      e.device_id), e.decision) AS detail,
  e.sha256,
  e.device_id AS device_id,
  e.executing_user AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution` AS e
LEFT JOIN (
  SELECT
    device_id,
    hostname
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`) AS h
ON
  e.device_id = h.device_id
UNION ALL
  ---------- Exemptions requested, for what, and by whom ----------
SELECT
  DISTINCT e.timestamp,
  (CASE e.state
      WHEN 'REQUESTED' THEN FORMAT('Exemption for %s was requested', IFNULL(h.hostname,  e.device_id))
      WHEN 'PENDING' THEN FORMAT('Exemption for %s is pending', IFNULL(h.hostname,
        e.device_id))
      WHEN 'APPROVED' THEN FORMAT('Exemption for %s was approved', IFNULL(h.hostname,  e.device_id))
      WHEN 'DENIED' THEN FORMAT('Exemption for %s was denied', IFNULL(h.hostname,
        e.device_id))
      WHEN 'ESCALATED' THEN FORMAT('Exemption for %s was escalated', IFNULL(h.hostname,  e.device_id))
      WHEN 'CANCELLED' THEN FORMAT('Exemption for %s was cancelled', IFNULL(h.hostname,
        e.device_id))
      WHEN 'REVOKED' THEN FORMAT('Exemption for %s was revoked', IFNULL(h.hostname,  e.device_id))
      WHEN 'EXPIRED' THEN FORMAT('Exemption for %s has expired', IFNULL(h.hostname,
        e.device_id))
      ELSE '(unknown state)' END) AS detail,
  CAST(NULL AS string) AS sha256,
  e.device_id AS device_id,
  CAST(NULL AS string) AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Exemption` AS e
LEFT JOIN (
  SELECT
    device_id,
    hostname
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`) AS h
ON
  e.device_id = h.device_id
UNION ALL
  ---------- All Host rows, multiplied across users ----------
SELECT
  DISTINCT h.timestamp,
  (CASE h.action
      WHEN 'FIRST_SEEN' THEN FORMAT('%s host %s was first seen', h.platform, IFNULL(h.hostname,  h.device_id))
      WHEN 'FULL_SYNC' THEN FORMAT('%s host %s performed a full sync', h.platform, IFNULL(h.hostname,
        h.device_id))
      WHEN 'MODE_CHANGE' THEN FORMAT('%s host %s changed mode to %s', h.platform, IFNULL(h.hostname,  h.device_id), h.mode)
      WHEN 'USERS_CHANGE' THEN FORMAT('%s host %s changed users to %s', h.platform, IFNULL(h.hostname,
        h.device_id), ARRAY_TO_STRING(h.users, ', '))
      WHEN 'COMMENT' THEN FORMAT('Comment on %s host %s: "%s"', h.platform, IFNULL(h.hostname,  h.device_id), h.comment)
      ELSE '(unknown action)' END) AS detail,
  CAST(NULL AS string) AS sha256,
  h.device_id AS device_id,
  user AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host` AS h
LEFT JOIN
  UNNEST(h.users) AS user
UNION ALL
  ---------- All User rows ----------
SELECT
  timestamp,
  (CASE u.action
      WHEN 'FIRST_SEEN' THEN FORMAT('User %s was first seen', SPLIT(u.email, '@')[  OFFSET  (0)])
      WHEN 'ROLE_CHANGE' THEN FORMAT('User %s changed roles to: %s', SPLIT(u.email, '@')[
    OFFSET
      (0)], ARRAY_TO_STRING(u.roles, ', '))
      WHEN 'COMMENT' THEN FORMAT('Comment on user %s: "%s"', SPLIT(u.email, '@')[  OFFSET  (0)], u.comment)
      ELSE '(unknown action)' END) AS detail,
  CAST(NULL AS string) AS sha256,
  CAST(NULL AS string) AS device_id,
  SPLIT(u.email, '@')[
OFFSET
  (0)] AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.User` AS u
UNION ALL
  ---------- All Vote rows (BINARY) ----------
SELECT
  DISTINCT v.timestamp,
  FORMAT('%s cast a %s%d vote for %s binary "%s"', SPLIT(v.voter, '@')[
  OFFSET
    (0)], IF(upvote,
      '+',
      '-'), weight, v.platform, IFNULL(n.name,
      SUBSTR(v.sha256, 0, 8))) AS detail,
  v.sha256,
  CAST(NULL AS string) AS device_id,
  SPLIT(v.voter, '@')[
OFFSET
  (0)] AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Vote` AS v
LEFT JOIN (
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
      file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution`
    WHERE
      file_name IS NOT NULL
    UNION DISTINCT
    SELECT
      DISTINCT sha256,
      first_seen_file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Binary`
    WHERE
      first_seen_file_name IS NOT NULL)
  GROUP BY
    sha256) AS n
ON
  v.sha256 = n.sha256
WHERE
  v.target_type = 'BINARY'
UNION ALL
  ---------- All Vote rows (CERTIFICATE) ----------
SELECT
  DISTINCT v.timestamp,
  FORMAT('%s cast a %s%d vote for certificate "%s"', SPLIT(v.voter, '@')[
  OFFSET
    (0)], IF(upvote,
      '+',
      '-'), weight, IFNULL(n.name,
      SUBSTR(v.sha256, 0, 8))) AS detail,
  v.sha256,
  CAST(NULL AS string) AS device_id,
  SPLIT(v.voter, '@')[
OFFSET
  (0)] AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Vote` AS v
LEFT JOIN (
  SELECT
    fingerprint AS sha256,
    common_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Certificate`
  WHERE
    common_name IS NOT NULL) AS n
ON
  n.sha256 = v.sha256
WHERE
  v.target_type = 'CERTIFICATE'
UNION ALL
  ---------- All Vote rows (PACKAGE) ----------
SELECT
  DISTINCT v.timestamp,
  FORMAT('%s cast a %s%d vote for %s package "%s"', SPLIT(v.voter, '@')[
  OFFSET
    (0)], IF(upvote,
      '+',
      '-'), weight, v.platform, IFNULL(n.name,
      SUBSTR(v.sha256, 0, 8))) AS detail,
  v.sha256,
  CAST(NULL AS string) AS device_id,
  SPLIT(v.voter, '@')[
OFFSET
  (0)] AS username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Vote` AS v
LEFT JOIN (
  SELECT
    bundle_hash AS sha256,
    bundle_id AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Bundle`
  WHERE
    bundle_id IS NOT NULL) AS n
ON
  v.sha256 = n.sha256
WHERE
  v.target_type = 'PACKAGE'
UNION ALL
  ---------- All Rule rows (BINARY) ----------
SELECT
  DISTINCT r.timestamp,
  FORMAT('%s %s rule for %s "%s" created%s%s', IF(r.scope = 'GLOBAL',
      'Global',
      'Local'), r.policy, LOWER(r.target_type), IFNULL(n.name,
      SUBSTR(r.sha256, 0, 8)), IF(r.scope = 'LOCAL',
      FORMAT(' for %s on %s', r.user, IFNULL(h.hostname,
          r.device_id)),
      ''), IF(r.comment IS NULL,
      '',
      FORMAT(' (Comment: %s)', r.comment))) AS detail,
  r.sha256,
  r.device_id,
  r.user
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Rule` AS r
JOIN (
  SELECT
    device_id,
    hostname
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`) AS h
ON
  r.device_id = h.device_id
LEFT JOIN (
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
      file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution`
    WHERE
      file_name IS NOT NULL
    UNION DISTINCT
    SELECT
      DISTINCT sha256,
      first_seen_file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Binary`
    WHERE
      first_seen_file_name IS NOT NULL)
  GROUP BY
    sha256) AS n
ON
  r.sha256 = n.sha256
WHERE
  r.target_type = 'BINARY'
UNION ALL
  ---------- All Rule rows (CERTIFICATE) ----------
SELECT
  DISTINCT r.timestamp,
  FORMAT('%s %s rule for %s "%s" created%s%s', IF(r.scope = 'GLOBAL',
      'Global',
      'Local'), r.policy, LOWER(r.target_type), IFNULL(n.name,
      SUBSTR(r.sha256, 0, 8)), IF(r.scope = 'LOCAL',
      FORMAT(' for %s on %s', r.user, IFNULL(h.hostname,
          r.device_id)),
      ''), IF(r.comment IS NULL,
      '',
      FORMAT(' (Comment: %s)', r.comment))) AS detail,
  r.sha256,
  r.device_id,
  r.user
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Rule` AS r
JOIN (
  SELECT
    device_id,
    hostname
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`) AS h
ON
  r.device_id = h.device_id
LEFT JOIN (
  SELECT
    fingerprint AS sha256,
    common_name AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Certificate`
  WHERE
    common_name IS NOT NULL) AS n
ON
  r.sha256 = n.sha256
WHERE
  r.target_type = 'CERTIFICATE'
UNION ALL
  ---------- All Rule rows (PACKAGE) ----------
SELECT
  DISTINCT r.timestamp,
  FORMAT('%s %s rule for %s "%s" created%s%s', IF(r.scope = 'GLOBAL',
      'Global',
      'Local'), r.policy, LOWER(r.target_type), IFNULL(n.name,
      SUBSTR(r.sha256, 0, 8)), IF(r.scope = 'LOCAL',
      FORMAT(' for %s on %s', r.user, IFNULL(h.hostname,
          r.device_id)),
      ''), IF(r.comment IS NULL,
      '',
      FORMAT(' (Comment: %s)', r.comment))) AS detail,
  r.sha256,
  r.device_id,
  r.user
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Rule` AS r
JOIN (
  SELECT
    device_id,
    hostname
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Host`) AS h
ON
  r.device_id = h.device_id
LEFT JOIN (
  SELECT
    bundle_hash AS sha256,
    bundle_id AS name
  FROM
    `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Bundle`
  WHERE
    bundle_id IS NOT NULL) AS n
ON
  r.sha256 = n.sha256
WHERE
  r.target_type = 'PACKAGE'
UNION ALL
  ---------- Bit9 local whitelisting latency ----------
SELECT
  l.fulfilled AS timestamp,
  FORMAT('Local whitelisting of "%s" fulfilled after %\'d minutes', IFNULL(n.name,
      SUBSTR(l.sha256, 0, 8)), TIMESTAMP_DIFF(l.fulfilled, l.executed, MINUTE)) AS detail,
  l.sha256,
  l.device_id,
  l.username
FROM
  `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Bit9LocalLatency` AS l
LEFT JOIN (
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
      DISTINCT sha256,
      file_name AS name
    FROM
      `YOUR_ORGANIZATION:YOUR_PROJECT.gae_streaming.Execution`
    WHERE
      file_name IS NOT NULL)
  GROUP BY
    sha256) AS n
ON
  l.sha256 = n.sha256
  ---------- Post-UNION section ----------
ORDER BY
  timestamp DESC

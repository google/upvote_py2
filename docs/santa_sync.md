## Santa Sync Server

Upvote ships with a Santa sync server developed in coordination with the Santa
team.

### Sync Procedure

The Upvote implementation conforms to the sync process
[described](https://santa.readthedocs.io/en/latest/introduction/syncing-overview/#flow-of-a-full-sync)
in the Santa documentation. See that page for further details.

### Security

All client communication is performed over HTTPS with XSRF protection enabled by
default (`SANTA_REQUIRE_XSRF` to change) to prevent clickjacking.

While there is no client authentication solution active by default, we do offer
an interface in which you can implement any scheme you see fit. However
depending on your threat model, running the sync service without authentication
isn't necessarily out of the question. An attacker sending traffic to the server
could only access the existing global rule set. They won't be able to view local
rule sets (without prior knowledge of the machine) and, notably, won't be able
to create or modify policy.

### Execution Mode

Santa clients can be configured in default-deny or default-approve mode (often
referred to as "lockdown" and "monitor," respectively). By default, Upvote
configures all Santa clients in lockdown mode. This can be changed using the
`DEFAULT_CLIENT_MODE` setting

#### Progressive Lockdown Rollout

For organizations, deploying Santa directly into lockdown mode may cause an
unwelcome shock to users and an unwelcome burden to administrators. To lessen
these issues, we suggest deploying Santa in monitor, whitelisting the most-used
software, and then slowly enabling lockdown. The recommended strategy is
outlined below:

1.  Install Santa on all of the hosts
2.  Deploy Upvote and configure it to default to monitor mode
3.  Wait for usage by the fleet
    -   Executions that would have been blocked were the host in lockdown mode,
        so-called `ALLOW_UNKNOWN` event types, are reported to Upvote.
4.  Analyze the software being used in order to identify and whitelist the
    signing certificates and applications that should be globally whitelisted
    -   For this sort of analysis, BigQuery will be invaluable so we recommend
        enabling BigQuery streaming (setup instructions [here](setup.md)).
5.  Begin to move hosts into lockdown mode
    -   This can be done gradually by configuring `LOCKDOWN_GROUP` to contain a
        progressively larger set of users.
    -   If any users run into issues during the rollout, the `MONITOR_GROUP` can
        be configured to include them.
6.  Move to lockdown-by-default by changing `SANTA_DEFAULT_CLIENT_MODE`

### Policy Syncing

Santa supports three different policy types:

-   `WHITELIST`: Allow execution
-   `BLACKLIST`: Block execution
-   `REMOVE`: Remove any pre-existing _policy entry_ (**NOT** the file itself)

...and two different Rule types:

-   `BINARY`: Apply the policy to a binary.
-   `CERTIFICATE`: Apply the policy to any binary signed by the signing
    certificate.

Rules are synced to Santa clients in order of their creation. Upvote maintains a
rule sync cursor for each Santa host so that only Rules created since the last
host sync need to be sent down to the client. Upvote will also limit synced
policy to Rules that are relevant to the host: All global Rules and local Rules
for that host.

#### Execution Path-based policy

While not described using rules, Santa does offer execution-path-based policy
via whitelist and blacklist regex host configuration parameters.

*WARNING:* We discourage use path-based whitelisting because it introduces the
potential to circumvent the lockdown execution protections that make Santa an
effective endpoint security tool.

That said, Upvote does offer a way to configure these parameters:

-   The `SANTA_DIRECTORY_WHITELIST_REGEX` and `SANTA_DIRECTORY_BLACKLIST_REGEX`
    settings configure the default value for all syncing hosts.
-   Per-host overrides can be made by setting
    `SantaHost.directory_whitelist_regex` and/or
    `SantaHost.directory_blacklist_regex` (although there is currently no way of
    setting these values through the UI).

### Policy Precedence

While not directly related to Upvote, Santa's policy evaluation logic does have
a great deal to do with administration strategy. In decreasing order of
precedence: `BINARY` -> `CERTIFICATE` -> `SCOPE` (i.e. path-based policy). One
benefit of this evaluation hierarchy is that it allows Upvote users to specify
exceptions to broad cert-based rules.

For example, if a signing certificate was determined to be untrustworthy, it
could be blacklisted but still permit a lone good binary signed by that
certificate to be whitelisted. Conversely, a single bad binary signed by a
whitelisted certificate could still be blacklisted.

## Bit9 Syncing

Unlike the Santa sync API which is a passive receiver of client-initiated syncs,
Bit9 integration relies on pulling from and pushing to the Bit9 service via the
REST API.

### Event Syncing

Upvote's event pull operation is implemented as a series of cron jobs which run
periodically to poll Bit9 for new events. These events are used to populate
Upvote entities that mirror the reported state.

*NOTE:* The frequency of the syncing cron jobs can be increased to trade off
increased cost for decreased event sync latency.

The sync procedure processes each host's events independently, thus avoiding
head-of-line blocking issues that can arise with rogue or broken agents.

### Policy Syncing

Upvote often creates new policy in batches (e.g. a user gets a new local
whitelist and has Rules created for each of their machines). In order to ensure
Bit9 consistency within these batches, they are grouped together and
collectively must be marked as committed. This quasi-transaction is stored in
Upvote using the `RuleChangeSet` model which, once committed, is deleted and
marks all `Bit9Rule`s as committed.

Because Upvote needs to go through Bit9 to make policy changes, there is some
non-negligible latency in synchronizing Upvote-generated policy back to Bit9. On
the frontend, users will be notified of in-progress policy synchronization with
a "(Pending)" indicator next to the blockable state.

**NOTE:** Policy-syncing latency is especially sensitive to slow Bit9 client
syncing.

### Source of Truth

In general, Upvote considers Bit9's reporting of state to be the source-of-truth
however there are some cases where Upvote's policies override those of Bit9,
namely global blacklists. There are other cases where Upvote requires its
prescribed state be reached as Bit9 doesn't report changes immediately.

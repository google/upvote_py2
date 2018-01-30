## How to Set Policy

### Blockable States

Blockables are created with a score of 0 and in the `UNTRUSTED` state.

<!-- mdformat off(GitHub Table) -->
| State                             | Default Score Threshold | Blockable Policy                                                                    |
|-----------------------------------|----:|----------------------------------------------------------------------------------------------------------|
| `BANNED`                          | -15 | Globally blacklisted.                                                                                    |
| `SUSPECT`                         | N/A | (Downvoted by an elevated-privilege user.) Cannot be voted on until an elevated-privilege user upvotes it. |
| `UNTRUSTED`                       |   0 | No policy set.                                                                                           |
| `APPROVED_FOR_LOCAL_WHITELISTING` |   5 | Users who have upvoted it are granted local whitelist policies.                                          |
| `GLOBALLY_WHITELISTED`            |  50 | Globally whitelisted.                                                                                    |
<!-- mdformat on -->

### Voting Lifecyle

All voting weights are configurable via the `VOTING_WEIGHTS` setting but, by
default, normal users vote with weight 1. Escalated-privilege users are able to
are able to select among the vote weights their role permits.

When a user votes on a Blockable, a `Vote` entity is created and their vote
weight is added or subtracted from that `Blockable`'s score depending on whether
they upvoted or downvoted the binary, respectively.

When a `Blockable` score crosses one of the score thresholds (configurable via
the `VOTING_THRESHOLD` setting), the `Blockable` moves into the state specified
by that threshold. State change can induce policy (in the form of `Rule`
entities) to be created, removed, or both depending on the nature of the change.
`Rule` entities may apply to a single `Host` or all `Host`s:

-   Local `Rule`s: non-empty host ID field that only applies the policy to the
    specified host.
-   Global `Rule`s: empty host ID field and their policy applies to all hosts in
    the fleet.

An example of a policy change would be when a `Blockable` reaches a score of 50
and transitions from the locally whitelisted to the globally whitelisted state.
In this case, all previous local `Rule`s are removed (actually "deactivated")
and a single global whitelist `Rule` is created.

If any user downvotes a Blockable, voting on that Blockable stops until a
privileged user has reviewed it and either upvoted it to unflag it or downvoted
it to keep normal voting disabled.

#### Resetting

`Blockable`s can be "reset" meaning that all votes and rules are deactivated,
the Blockable score returns to 0, and the Blockable's state to `UNTRUSTED`.

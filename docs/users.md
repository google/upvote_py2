## Users in Upvote

User-bound policies are a great benefit to social whitelisting in Upvote. But
while they achieve a better experience for the user, they introduce integration
complexities with whitelisting clients. Upvote must associate execution events
reported by clients to one or more "users" on the server. In this context, a
user is uniquely identified by the email address they use to authenticate to the
App Engine frontend (which needs to be a Google- or G Suite-hosted account).

Upvote needs to somehow tie the data contained in the execution events to a set
of email addresses.

This is done in two steps. First, the execution event is translated to one or
more "username strings" using the algorithm selected by the `EVENT_CREATION`
setting. Then each username string is converted to a user email using the
functions in [user\_map.py](../upvote/gae/shared/common/user_map.py) which, by
default, simply appends "`@`" and the `USER_EMAIL_DOMAIN` setting.

For the extraction of the username strings, Upvote offers two `EVENT_CREATION`
configuration modes: 1. `HOST_OWNERS` (default): Return the "owners" of the
event's host 2. `EXECUTING_USER`: Return the login user that triggered execution

The configuration you choose depends on the client(s) you intend on running.

### Santa

For Santa, the default `HOST_OWNERS` configuration is likely the easiest to
deploy.

When the `HOST_OWNERS` option is used, the Santa client's "`MachineOwner`"
configuration value (see the [Santa docs
page](https://santa.readthedocs.io/en/latest/deployment/configuration/) for
additional config information) is used as the username string. This permits the
administrator to provision each client with the username that matches the
intended user's email.

Since `EXECUTING_USER` uses the login user as the username string, it requires
each login user to have a close, one-to-one relationship to the user email.
Using the default behavior in [user\_map.py], each login user would need to
exactly match username portion of the associated user's email address (e.g.
`joeavg` -> `joeavg@foo.com`). However if this _does_ fit the indended
deployment, `EXECUTING_USER` should be the preferred configuration.

### Bit9

For Bit9, there is no supported way of provisioning a value for the username
string of the Bit9 client.

As a result, both the `HOST_OWNERS` and `EXECUTING_USER` settings will derive
the username string from the login users on the host:

-   `HOST_OWNERS` will associate with all login users who have ever triggered
    events reported to Bit9.
-   `EXECUTING_USER` will only associate with the login user who triggered the
    given event.

This means that Bit9 integration will only be possible in deployments where the
login user can be one-to-one mapped to the intended email address. Using the
default behavior in [user\_map.py](../upvote/gae/shared/common/user_map.py),
this each login user (stripped of the domain) would need to exactly match
username portion of the associated user's email address (e.g. `FOO\\joeavg` ->
`joeavg` -> `joeavg@foo.com`).

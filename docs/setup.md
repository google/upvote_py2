## Setup

### Prerequisites

1.  A Google Account
    *   Google App Engine authentication requires you and anyone you intend to
        access the service to do so using a Google Account (this includes GSuite
        accounts).
2.  An installation of Bazel, an open-source build system
    *   Installation instructions can be found
        [here](https://docs.bazel.build/versions/master/install.html).
3.  An installation of the Google Cloud SDK
    *   Installation instructions can be found
        [here](https://cloud.google.com/sdk/downloads).
    *   This installs the `gcloud` command-line tool which provides an
        easy-to-use interface for Google Cloud resources

### Initialization

1.  Clone this repo
    *   `git clone https://github.com/google/upvote`
2.  Create a GCP project
    *   No need to do any other manual setup.
3.  Export your new project's ID to the `PROJ_ID` environment variable
    *   `export PROJ_ID="my-proj-id"`
4.  Run the initialization script in the Upvote root directory
    *   `./init_project.sh`
    *   You may be prompted to set some parameters for your App Engine app.
    *   The first deployment will take several minutes so hang tight.

### Settings

Next, there will be a number of settings to review and configure. Upvote
settings are almost exclusively located in
[settings.py](../upvote/gae/shared/common/settings.py) (any exceptions will be
noted) so be sure to look there for any settings mentioned in the docs.

#### User Configuration

First, set the `USER_EMAIL_DOMAIN` setting to the email domain you expect users
to connect with. Unfortunately, because of a limitation of App Engine
authentication, this domain needs to be a Google-hosted account (e.g. a G Suite
GMail account). You should also set the `USER_EMAIL_DOMAIN` constant in
[app-constants.js](../upvote/gae/modules/upvote_app/frontend/admin_ui/app-constants.js)
to the same value.

Please go to the [users](users.md) section of the docs for the full user
configuration instructions.

##### Bit9

Bit9 reports logged-in users in down-level domain format (e.g. `DOMAIN\USER`) so
Upvote first strips off the domain (the domain to be stripped is configured with
the `AD_DOMAIN` setting), then converts the user to lowercase, then applies
`UsernameToEmail`.

`upvote/shared/constants.py` `USER_EMAIL_DOMAIN = 'gmail.com'`

### Groups

Next, you need to give yourself admin rights to the application. To do so, you
must modify the user grouping interface Upvote uses to assign elevated-privilege
roles. Upvote provides a simple default implementation of user grouping (found
in `GroupManager` in [groups.py](upvote/gae/shared/common/groups.py)) so all you
need to do is add your email (and those of any other admins) to the
'`admin-users`' group. This static solution should suffice for small
organizations and for individual users.

However for larger organizations, the GroupManager class implementations can be
replaced by API calls to an HR system or similar company-specific grouping
mechanism.

After you've added yourself to this group, you must enable role syncing and
redeploy the application:

```shell
./manage_crons.py enable groups
bazel run upvote/gae:monolith_binary.deploy -- ${PROJ_ID}
```

Once the deploy completes, the `/api/web/cron/roles/sync` cron can be manually
triggered from the Cloud Console's [cron
page](https://console.cloud.google.com/appengine/taskqueues/cron). You can
confirm this was successful when you can access the admin site at
`https://<my-app>.appspot.com/admin/settings`.

### (Optional) VirusTotal

VirusTotal is a binary reputation aggregator that can be used to inform trust
decisions. The API provides analysis results from many anti-virus and
application scanners and is free to use up to a certain usage limit (4 req/min).

To integrate with VirusTotal, perform the following steps:

1.  Sign up for account at https://www.virustotal.com/#/join-us
2.  Activate your account and log in
3.  Copy API Key at https://www.virustotal.com/#/settings/apikey
4.  Go to `https://<my-app>.appspot.com/admin/settings`
5.  Enter the copied key into "API Keys > VirusTotal API Key Value" and press
    the save button at the lower right.

### (Optional) Monitoring

Upvote has many metrics tracked throughout the code however the current
implementation is a no-op. If you would like to have access to these metrics,
you will need to implement the indicated stubs in
[monitoring.py](../upvote/gae/shared/common/monitoring.py)

Likely the easiest way to make use of these stubs is through integration with
[Cloud Monitoring](https://cloud.google.com/monitoring/). However, you may have
an internal system by which you do monitoring in which case you can implement
your own sync procedure.

### Platform Setup

Now each binary whitelisting platform you intend on running with Upvote needs to
be setup and configured.

#### Santa

The following are the Santa configuration parameters relevant to Upvote as well
as the suggested values:

<!-- mdformat off(GitHub Table) -->
plist key         | Suggested Value
----------------- | -------------------------------------------------------
`MachineOwner`    | Username of the owner (see [user](users.md) docs)
`ClientMode`      | Managed by Upvote: 1 (allow-unknown or "monitor") or 2 (deny-unknown or "lockdown")
`SyncBaseURL`     | "`https://<my-app>.appspot.com/api/santa/`"
`EventDetailURL`  | "`https://<my-app>.appspot.com/blockables/%file\_sha%`"
`EventDetailText` | "Open in Upvote..."
<!-- mdformat on -->

See the [Santa docs
page](https://santa.readthedocs.io/en/latest/deployment/configuration/) for a
full list of configuration options.

#### Bit9

1.  Set the `AD_DOMAIN` and `AD_HOSTNAME` settings.
2.  Go to `https://<my-app>.appspot.com/admin/settings`
3.  Enter your Bit9 REST API key into "API Keys > Bit9 API Key Value" and press
    the save button at the lower right.
4.  Enable the Bit9 syncing crons: `./manage_crons.py enable bit9`

After that configuration is complete, all that's necessary is to redeploy the
app:

```shell
bazel run upvote/gae:monolith_binary.deploy -- ${PROJ_ID} app.yaml bit9_api.yaml
```

##### Proxy

If your connection to Bit9 requires a proxy, you can set the `HTTPS_PROXY` env
variable [bit9_api.yaml](../upvote/gae/bit9_api.yaml):

```yaml
env_variables:
  HTTPS_PROXY: 'http://122.110.1.10:1080'
```

For further information on App Engine environment variables, take a look at the
[docs](https://cloud.google.com/appengine/docs/standard/python/config/appref#Python_app_yaml_Defining_environment_variables)

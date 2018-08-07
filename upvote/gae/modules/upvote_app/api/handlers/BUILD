load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "all",
    deps = [
        ":alerts",
        ":base",
        ":blockables",
        ":constants",
        ":emergency",
        ":events",
        ":hosts",
        ":index_handler",
        ":lookups",
        ":rules",
        ":settings",
        ":users",
        ":votes",
    ],
)

py_library(
    name = "alerts",
    srcs = ["alerts.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:alert",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "blockables",
    srcs = ["blockables.py"],
    deps = [
        ":base",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/voting:api",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "constants",
    srcs = ["constants.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "emergency",
    srcs = ["emergency.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:cache",
        "//upvote/gae/shared/common:big_red",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "events",
    srcs = ["events.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:user_map",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "hosts",
    srcs = ["hosts.py"],
    deps = [
        ":base",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/datastore/models:tickets",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "lookups",
    srcs = ["lookups.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/lib/analysis:api",
        "//upvote/gae/lib/analysis/virustotal:constants",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
    ],
)

py_library(
    name = "rules",
    srcs = ["rules.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "settings",
    srcs = ["settings.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:virustotal",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/utils:string_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "users",
    srcs = ["users.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "votes",
    srcs = ["votes.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/voting:api",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "base",
    srcs = ["base.py"],
    deps = [
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:json_utils",
        "//upvote/gae/utils:string_utils",
    ],
)

py_appengine_library(
    name = "index_handler",
    srcs = ["index_handler.py"],
    deps = [
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:template_utils",
        "//upvote/gae/utils:xsrf_utils",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "base_test",
    size = "small",
    srcs = ["base_test.py"],
    deps = [
        ":base",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "index_handler_test",
    size = "small",
    srcs = ["index_handler_test.py"],
    deps = [
        ":index_handler",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "alerts_test",
    size = "small",
    srcs = ["alerts_test.py"],
    deps = [
        ":alerts",
        "//external:mock",
        "//upvote/gae/datastore/models:alert",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/gae/utils:json_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "blockables_test",
    size = "small",
    srcs = ["blockables_test.py"],
    deps = [
        ":blockables",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/voting:api",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "constants_test",
    size = "small",
    srcs = ["constants_test.py"],
    deps = [
        ":constants",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "emergency_test",
    size = "small",
    srcs = ["emergency_test.py"],
    deps = [
        ":emergency",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
    ],
)

upvote_appengine_test(
    name = "events_test",
    size = "small",
    srcs = ["events_test.py"],
    deps = [
        ":events",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "hosts_test",
    size = "small",
    srcs = ["hosts_test.py"],
    deps = [
        ":hosts",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/datastore/models:tickets",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:test_utils",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "lookups_test",
    size = "small",
    srcs = ["lookups_test.py"],
    deps = [
        ":lookups",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/analysis:api",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "rules_test",
    size = "small",
    srcs = ["rules_test.py"],
    deps = [
        ":rules",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
    ],
)

upvote_appengine_test(
    name = "settings_test",
    size = "small",
    srcs = ["settings_test.py"],
    deps = [
        ":settings",
        "//external:mock",
        "//upvote/gae/datastore/models:cache",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
    ],
)

upvote_appengine_test(
    name = "users_test",
    size = "small",
    srcs = ["users_test.py"],
    deps = [
        ":users",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "votes_test",
    size = "small",
    srcs = ["votes_test.py"],
    deps = [
        ":votes",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/modules/upvote_app/api",
    ],
)

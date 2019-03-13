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
        ":blockables",
        ":emergency",
        ":events",
        ":exemptions",
        ":features",
        ":hosts",
        ":index",
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
        ":monitoring",
        "//upvote/gae/datastore/models:alert",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "blockables",
    srcs = ["blockables.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:note",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/voting:api",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "emergency",
    srcs = ["emergency.py"],
    deps = [
        "//upvote/gae/datastore/models:cache",
        "//upvote/gae/shared/common:big_red",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "events",
    srcs = ["events.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "exemptions",
    srcs = ["exemptions.py"],
    deps = [
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/exemption:api",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "features",
    srcs = ["features.py"],
    deps = [
        "//upvote/gae/utils:group_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:user_utils",
    ],
)

py_library(
    name = "hosts",
    srcs = ["hosts.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/exemption:api",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "lookups",
    srcs = ["lookups.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/lib/analysis:api",
        "//upvote/gae/lib/analysis/virustotal:constants",
        "//upvote/gae/utils:handler_utils",
    ],
)

py_library(
    name = "rules",
    srcs = ["rules.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/utils:handler_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "settings",
    srcs = ["settings.py"],
    deps = [
        ":monitoring",
        "//upvote/gae:settings",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:string_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "users",
    srcs = ["users.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "votes",
    srcs = ["votes.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/lib/voting:api",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":all",
        ":monitoring",
        "//upvote/gae:settings",
        "//upvote/gae/utils:handler_utils",
    ],
)

py_appengine_library(
    name = "index",
    srcs = ["index.py"],
    deps = [
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:template_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    visibility = ["//visibility:private"],
    deps = [
        "//upvote/gae/utils:monitoring_utils",
        "//upvote/monitoring:metrics",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "index_test",
    size = "small",
    srcs = ["index_test.py"],
    deps = [
        ":index",
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
        "//upvote/gae/datastore/models:note",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/voting:api",
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
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "exemptions_test",
    size = "small",
    srcs = ["exemptions_test.py"],
    deps = [
        ":exemptions",
        "//external:mock",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "features_test",
    size = "small",
    srcs = ["features_test.py"],
    deps = [
        ":features",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/utils:group_utils",
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
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:test_utils",
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
        "//upvote/gae/utils:env_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "main_test",
    size = "small",
    srcs = ["main_test.py"],
    deps = [
        ":main",
        "//upvote/gae/lib/testing:basetest",
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
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/lib/testing:basetest",
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
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/lib/testing:basetest",
    ],
)

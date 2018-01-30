load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "all_srcs",
    deps = [
        ":auditlogs",
        ":base",
        ":blockables",
        ":constants",
        ":emergency",
        ":events",
        ":export",
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
    name = "auditlogs",
    srcs = ["auditlogs.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/models:base",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "blockables",
    srcs = ["blockables.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/bit9_api:change_set",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/modules/upvote_app/lib:voting",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:model_mapping",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
        "//upvote/gae/shared/models:santa",
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
        "//upvote/gae/shared/common:big_red",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:cache",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "events",
    srcs = ["events.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
        "//upvote/gae/shared/models:santa",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "export",
    srcs = ["export.py"],
    deps = [
        ":base",
        "//external:gcloud_auth",
        "//external:gcloud_bigquery",
        "//upvote/gae/modules/upvote_app/lib:bigquery_schema",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "hosts",
    srcs = ["hosts.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bigquery",
        "//upvote/gae/shared/models:santa",
        "//upvote/gae/shared/models:tickets",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "lookups",
    srcs = ["lookups.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/binary_health",
        "//upvote/gae/shared/binary_health/virustotal:constants",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
    ],
)

py_library(
    name = "rules",
    srcs = ["rules.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:santa",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "settings",
    srcs = ["settings.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:virustotal",
        "//upvote/shared:constants",
        "//upvote/shared:utils",
    ],
)

py_library(
    name = "users",
    srcs = ["users.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:base",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "votes",
    srcs = ["votes.py"],
    deps = [
        ":base",
        "//upvote/gae/modules/upvote_app/api:monitoring",
        "//upvote/gae/modules/upvote_app/lib:voting",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "base",
    srcs = ["base.py"],
    deps = [
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:json_utils",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:utils",
        "//upvote/shared:utils",
    ],
)

py_appengine_library(
    name = "index_handler",
    srcs = ["index_handler.py"],
    deps = [
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:template_utils",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/common:xsrf_utils",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "auditlogs_test",
    size = "small",
    srcs = ["auditlogs_test.py"],
    deps = [
        ":auditlogs",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:test_utils",
    ],
)

upvote_appengine_test(
    name = "base_test",
    size = "small",
    srcs = ["base_test.py"],
    deps = [
        ":base",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:test_utils",
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
        "//upvote/gae/shared/common:basetest",
    ],
)

upvote_appengine_test(
    name = "blockables_test",
    size = "small",
    srcs = ["blockables_test.py"],
    deps = [
        ":blockables",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:santa",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/gae/shared/models:utils",
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
        "//upvote/gae/shared/common:basetest",
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
        "//upvote/gae/shared/common:basetest",
    ],
)

upvote_appengine_test(
    name = "events_test",
    size = "small",
    srcs = ["events_test.py"],
    deps = [
        ":events",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/gae/shared/models:utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "export_test",
    size = "small",
    srcs = ["export_test.py"],
    deps = [
        ":export",
        "//external:gcloud_bigquery",
        "//external:mock",
        "//upvote/gae/modules/upvote_app/lib:bigquery_schema",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
    ],
)

upvote_appengine_test(
    name = "hosts_test",
    size = "small",
    srcs = ["hosts_test.py"],
    deps = [
        ":hosts",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:test_utils",
        "//upvote/gae/shared/common:xsrf_utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:santa",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/gae/shared/models:tickets",
        "//upvote/gae/shared/models:utils",
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
        "//upvote/gae/shared/binary_health",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:test_utils",
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
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:santa",
        "//upvote/gae/shared/models:test_utils",
    ],
)

upvote_appengine_test(
    name = "settings_test",
    size = "small",
    srcs = ["settings_test.py"],
    deps = [
        ":settings",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:cache",
    ],
)

upvote_appengine_test(
    name = "users_test",
    size = "small",
    srcs = ["users_test.py"],
    deps = [
        ":users",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:test_utils",
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
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/gae/shared/models:utils",
    ],
)

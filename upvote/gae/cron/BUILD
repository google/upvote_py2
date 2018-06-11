load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        ":export",
        ":main",
        ":monitoring",
        ":roles",
    ],
)

py_appengine_library(
    name = "roles",
    srcs = ["roles.py"],
    deps = [
        "//upvote/gae/shared/common:groups",
        "//upvote/gae/shared/common:query_utils",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/common:utils",
    ],
)

py_appengine_library(
    name = "export",
    srcs = ["export.py"],
    deps = [
        ":monitoring",
        "//external:gcloud_auth",
        "//external:gcloud_bigquery",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/modules/upvote_app/lib:bigquery_schema",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:time_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/shared/common:monitoring",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":export",
        ":roles",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "roles_test",
    size = "small",
    srcs = ["roles_test.py"],
    deps = [
        ":roles",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:groups",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "export_test",
    size = "small",
    srcs = ["export_test.py"],
    deps = [
        ":export",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/gae/shared/common:utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "main_test",
    size = "small",
    srcs = ["main_test.py"],
    deps = [
        ":main",
        "//upvote/gae/shared/common:basetest",
    ],
)

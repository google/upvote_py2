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
        ":sync",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:utils",
    ],
)

py_appengine_library(
    name = "sync",
    srcs = ["sync.py"],
    deps = [
        "//common:datastore_locks",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:utils",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:intermodule_utils",
        "//upvote/gae/utils:time_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "cron",
    srcs = ["cron.py"],
    deps = [
        ":sync",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:utils",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/taskqueue:utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":cron",
        ":sync",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/shared/common:handlers",
    ],
)

py_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/shared/common:settings",
    ],
)

py_appengine_library(
    name = "bit9_api_library",
    data = [
        "//upvote/gae:bit9_api.yaml",
    ],
    deps = [
        ":cron",
        ":main",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/shared/common:handlers",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "sync_test",
    srcs = ["sync_test.py"],
    deps = [
        ":sync",
        ":test_utils",
        "//common:datastore_locks",
        "//external:mock",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:test_utils",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "cron_test",
    srcs = ["cron_test.py"],
    deps = [
        ":cron",
        ":sync",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "main_test",
    size = "small",
    srcs = ["main_test.py"],
    deps = [
        ":bit9_api_library",
        "//upvote/gae/lib/testing:basetest",
    ],
)

# Test Data
# ==============================================================================

filegroup(
    name = "fake_credentials",
    srcs = ["fake_credentials.json"],
)

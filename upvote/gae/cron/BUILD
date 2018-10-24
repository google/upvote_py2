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
        ":bit9_syncing",
        ":datastore_backup",
        ":main",
        ":role_syncing",
    ],
)

py_appengine_library(
    name = "bit9_syncing",
    srcs = ["bit9_syncing.py"],
    deps = [
        "//common:datastore_locks",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:intermodule_utils",
        "//upvote/gae/utils:time_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "datastore_backup",
    srcs = ["datastore_backup.py"],
    deps = [
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "role_syncing",
    srcs = ["role_syncing.py"],
    deps = [
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/utils:group_utils",
        "//upvote/gae/utils:iter_utils",
    ],
)

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":bit9_syncing",
        ":datastore_backup",
        ":role_syncing",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "bit9_syncing_test",
    srcs = ["bit9_syncing_test.py"],
    deps = [
        ":bit9_syncing",
        "//common:datastore_locks",
        "//external:mock",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bit9",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:bit9test",
        "//upvote/gae/lib/testing:test_utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/utils:handler_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "datastore_backup_test",
    size = "small",
    srcs = ["datastore_backup_test.py"],
    deps = [
        ":datastore_backup",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/gae/utils:env_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "role_syncing_test",
    size = "small",
    srcs = ["role_syncing_test.py"],
    deps = [
        ":role_syncing",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/utils:group_utils",
        "//upvote/shared:constants",
    ],
)

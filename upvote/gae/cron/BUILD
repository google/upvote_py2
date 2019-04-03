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
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:note",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:utils",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:time_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "datastore_backup",
    srcs = ["datastore_backup.py"],
    deps = [
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:monitoring_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "role_syncing",
    srcs = ["role_syncing.py"],
    deps = [
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/utils:group_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:iter_utils",
        "//upvote/gae/utils:monitoring_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "exemption_upkeep",
    srcs = ["exemption_upkeep.py"],
    deps = [
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/exemption:api",
        "//upvote/gae/lib/exemption:monitoring",
        "//upvote/gae/lib/exemption:notify",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:group_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":bit9_syncing",
        ":datastore_backup",
        ":exemption_upkeep",
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
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:note",
        "//upvote/gae/datastore/models:policy",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:constants",
        "//upvote/gae/lib/bit9:monitoring",
        "//upvote/gae/lib/bit9:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:bit9test",
        "//upvote/gae/lib/testing:test_utils",
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
        "//upvote/gae:settings",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/utils:group_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "exemption_upkeep_test",
    srcs = ["exemption_upkeep_test.py"],
    deps = [
        ":exemption_upkeep",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/lib/exemption:api",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

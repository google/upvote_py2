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
        ":datastore_backup",
        ":main",
        ":role_syncing",
    ],
)

py_appengine_library(
    name = "datastore_backup",
    srcs = ["datastore_backup.py"],
    deps = [
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/utils:env_utils",
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
        ":datastore_backup",
        ":role_syncing",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

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

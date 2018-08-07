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
        ":roles",
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
    name = "roles",
    srcs = ["roles.py"],
    deps = [
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/shared/common:groups",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/utils:iter_utils",
    ],
)

py_appengine_library(
    name = "main",
    srcs = ["main.py"],
    deps = [
        ":datastore_backup",
        ":roles",
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
    name = "roles_test",
    size = "small",
    srcs = ["roles_test.py"],
    deps = [
        ":roles",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:groups",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        ":sync",
    ],
)

py_appengine_library(
    name = "main",
    srcs = [
        "main.py",
    ],
    deps = [
        ":sync",
        "//upvote/gae/utils:handler_utils",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/utils:monitoring_utils",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "sync",
    srcs = ["sync.py"],
    deps = [
        ":auth",
        ":monitoring",
        "//external:six",
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/shared/common:big_red",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "auth",
    srcs = ["auth.py"],
)

# AppEngine Unit Tests
# ==============================================================================

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
    name = "monitoring_test",
    size = "small",
    srcs = ["monitoring_test.py"],
    deps = [
        ":monitoring",
        "//common/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "sync_test",
    size = "small",
    srcs = ["sync_test.py"],
    deps = [
        ":sync",
        "//external:mock",
        "//external:six",
        "//external:webtest",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/utils:handler_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "api",
    srcs = ["api.py"],
    deps = [
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/lib/bit9:change_set",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "api_test",
    size = "medium",
    srcs = ["api_test.py"],
    deps = [
        ":api",
        "//external:mock",
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

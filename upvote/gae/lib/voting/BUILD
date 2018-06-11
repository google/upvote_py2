load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "api",
    srcs = ["api.py"],
    deps = [
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/analysis:metrics",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/taskqueue:utils",
        "//upvote/gae/utils:intermodule_utils",
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
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

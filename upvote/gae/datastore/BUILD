package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        "//upvote/gae/datastore/models:all",
    ],
)

py_appengine_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        ":utils",
        "//external:mock",
        "//external:six",
        "//upvote/gae:settings",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/datastore/models:policy",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/datastore/models:vote",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//external:six",
        "//upvote/shared:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "//external:mock",
        "//external:six",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "test_utils_test",
    size = "small",
    srcs = ["test_utils_test.py"],
    deps = [
        ":test_utils",
        "//upvote/gae:settings",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:event",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:user",
        "//upvote/gae/lib/testing:basetest",
    ],
)

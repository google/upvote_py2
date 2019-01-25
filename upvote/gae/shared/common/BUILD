load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "all",
    deps = [
        ":big_red",
        "//upvote/gae:settings",
        "//upvote/gae/utils:json_utils",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "big_red",
    srcs = ["big_red.py"],
    deps = [
        "//upvote/gae/datastore/models:cache",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "big_red_test",
    size = "small",
    srcs = ["big_red_test.py"],
    deps = [
        ":big_red",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

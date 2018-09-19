load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    deps = [
        "//upvote/gae/datastore:utils",
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
        "//common/testing:basetest",
        "//upvote/gae/lib/testing:basetest",
    ],
)

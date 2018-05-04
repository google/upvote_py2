load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    visibility = [
        "//upvote",
        "//upvote/gae/cron:__pkg__",
        "//upvote/gae/datastore/models:__pkg__",
        "//upvote/gae/modules/bit9_api:__pkg__",
        "//upvote/gae/modules/santa_api:__pkg__",
        "//upvote/gae/modules/upvote_app/api/handlers:__pkg__",
        "//upvote/gae/modules/upvote_app/lib:__pkg__",
    ],
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
        "//upvote/gae/shared/common:basetest",
    ],
)

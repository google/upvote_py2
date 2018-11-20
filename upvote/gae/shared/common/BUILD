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

py_library(
    name = "user_map",
    srcs = ["user_map.py"],
    deps = [
        "//upvote/gae:settings",
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

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = ["//upvote/shared:constants"],
)

py_appengine_library(
    name = "template_utils",
    srcs = ["template_utils.py"],
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

upvote_appengine_test(
    name = "template_utils_test",
    size = "small",
    srcs = ["template_utils_test.py"],
    data = ["//upvote/gae/shared/templates"],
    deps = [
        ":template_utils",
        "//common/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "user_map_test",
    size = "small",
    srcs = ["user_map_test.py"],
    deps = [
        ":user_map",
        "//upvote/gae/lib/testing:basetest",
    ],
)

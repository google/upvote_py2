load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "intermodule_utils",
    srcs = ["intermodule_utils.py"],
    deps = [
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "json_utils",
    srcs = ["json_utils.py"],
)

py_appengine_library(
    name = "memcache_utils",
    srcs = ["memcache_utils.py"],
    deps = [
        "//common:memcache_decorator",
    ],
)

py_appengine_library(
    name = "string_utils",
    srcs = ["string_utils.py"],
)

py_appengine_library(
    name = "time_utils",
    srcs = ["time_utils.py"],
    deps = [
        "//upvote/gae/modules/bit9_api:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "intermodule_utils_test",
    size = "small",
    srcs = ["intermodule_utils_test.py"],
    deps = [
        ":intermodule_utils",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:settings_utils",
    ],
)

upvote_appengine_test(
    name = "json_utils_test",
    size = "small",
    srcs = ["json_utils_test.py"],
    deps = [
        ":json_utils",
        "//common/testing:basetest",
        "//upvote/gae/datastore/models:santa",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "memcache_utils_test",
    size = "small",
    srcs = ["memcache_utils_test.py"],
    deps = [
        ":memcache_utils",
        "//common/testing:basetest",
        "//external:mock",
    ],
)

upvote_appengine_test(
    name = "string_utils_test",
    size = "small",
    srcs = ["string_utils_test.py"],
    deps = [
        ":string_utils",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "time_utils_test",
    size = "small",
    srcs = ["time_utils_test.py"],
    deps = [
        ":time_utils",
        "//external:mock",
        "@absl_git//absl/testing:absltest",
    ],
)

load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "env_utils",
    srcs = ["env_utils.py"],
    deps = [
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "intermodule_utils",
    srcs = ["intermodule_utils.py"],
    deps = [
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "handler_utils",
    srcs = ["handler_utils.py"],
    deps = [
        ":env_utils",
        ":json_utils",
        ":string_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:user",
    ],
)

py_appengine_library(
    name = "iter_utils",
    srcs = ["iter_utils.py"],
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
        "//upvote/gae/lib/bit9:constants",
    ],
)

py_appengine_library(
    name = "xsrf_utils",
    srcs = ["xsrf_utils.py"],
    deps = [
        "//external:oauth2client",
    ],
)

py_appengine_library(
    name = "group_utils",
    srcs = ["group_utils.py"],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "env_utils_test",
    size = "small",
    srcs = ["env_utils_test.py"],
    deps = [
        ":env_utils",
        "//common/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "intermodule_utils_test",
    size = "small",
    srcs = ["intermodule_utils_test.py"],
    deps = [
        ":intermodule_utils",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:settings_utils",
    ],
)

upvote_appengine_test(
    name = "handler_utils_test",
    size = "small",
    srcs = ["handler_utils_test.py"],
    deps = [
        ":handler_utils",
        "//common/testing:basetest",
        "//external:mock",
        "//external:webob",
        "//external:webtest",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "iter_utils_test",
    size = "small",
    srcs = ["iter_utils_test.py"],
    deps = [
        ":iter_utils",
        "//common/testing:basetest",
        "//upvote/shared:constants",
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

upvote_appengine_test(
    name = "xsrf_utils_test",
    size = "small",
    srcs = ["xsrf_utils_test.py"],
    deps = [
        ":xsrf_utils",
        "//external:mock",
        "//external:oauth2client",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

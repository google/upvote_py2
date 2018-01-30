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
        ":json_utils",
        ":model_mapping",
        ":query_utils",
        ":settings",
    ],
)

py_library(
    name = "model_mapping",
    srcs = ["model_mapping.py"],
    deps = [
        "//upvote/gae/shared/models:santa",
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "user_map",
    srcs = ["user_map.py"],
    deps = [
        ":settings",
    ],
)

py_library(
    name = "fake_monotonic",
    srcs = ["fake_monotonic.py"],
)

py_library(
    name = "google_cloud_lib_fixer",
    srcs = ["google_cloud_lib_fixer.py"],
    deps = [
        ":fake_monotonic",
        "//external:requests_toolbelt",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "big_red",
    srcs = ["big_red.py"],
    deps = [
        "//upvote/gae/shared/models:cache",
    ],
)

py_appengine_library(
    name = "memcache_utils",
    srcs = ["memcache_utils.py"],
    deps = [
        "//common:memcache_decorator",
    ],
)

py_appengine_library(
    name = "json_utils",
    srcs = ["json_utils.py"],
)

py_appengine_library(
    name = "query_utils",
    srcs = ["query_utils.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "handlers",
    srcs = ["handlers.py"],
    deps = [
        ":json_utils",
        ":utils",
    ],
)

py_appengine_library(
    name = "intermodule",
    srcs = ["intermodule.py"],
    deps = [
        ":settings",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    deps = [
        ":settings",
        ":settings_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "basetest",
    testonly = 1,
    srcs = ["basetest.py"],
    data = ["//upvote/gae:index.yaml"],
    deps = [
        ":handlers",
        ":xsrf_utils",
        "//common/testing:basetest",
        "//external:mock",
        "//external:oauth2client",
        "//external:webob",
        "//external:webtest",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "settings",
    srcs = ["settings.py"],
    deps = [
        ":settings_utils",
        "//common:context",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "settings_utils",
    srcs = ["settings_utils.py"],
    deps = [
        "//external:six",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = ["//upvote/shared:constants"],
)

py_appengine_library(
    name = "taskqueue_utils",
    srcs = ["taskqueue_utils.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "template_utils",
    srcs = ["template_utils.py"],
)

py_appengine_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        "//external:mock",
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
    name = "groups",
    srcs = ["groups.py"],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "big_red_test",
    size = "small",
    srcs = ["big_red_test.py"],
    deps = [
        ":big_red",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:santa",
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
    name = "json_utils_test",
    size = "small",
    srcs = ["json_utils_test.py"],
    deps = [
        ":json_utils",
        "//common/testing:basetest",
        "//upvote/gae/shared/models:santa",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "settings_utils_test",
    size = "small",
    srcs = ["settings_utils_test.py"],
    deps = [
        ":basetest",
        ":settings",
        ":settings_utils",
    ],
)

upvote_appengine_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "//common/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "handlers_test",
    size = "small",
    srcs = ["handlers_test.py"],
    deps = [
        ":basetest",
        ":handlers",
        "//common/testing:basetest",
        "//external:mock",
        "//external:webob",
        "//external:webtest",
    ],
)

upvote_appengine_test(
    name = "query_utils_test",
    srcs = ["query_utils_test.py"],
    deps = [
        ":basetest",
        ":query_utils",
        "//external:mock",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "intermodule_test",
    size = "small",
    srcs = ["intermodule_test.py"],
    deps = [
        ":basetest",
        ":intermodule",
        ":settings",
        ":settings_utils",
        "//external:mock",
    ],
)

upvote_appengine_test(
    name = "taskqueue_utils_test",
    size = "small",
    srcs = ["taskqueue_utils_test.py"],
    deps = [
        ":basetest",
        ":taskqueue_utils",
        "//common/testing:basetest",
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
        ":basetest",
        ":user_map",
    ],
)

upvote_appengine_test(
    name = "xsrf_utils_test",
    size = "small",
    srcs = ["xsrf_utils_test.py"],
    deps = [
        ":basetest",
        ":xsrf_utils",
        "//external:mock",
        "//external:oauth2client",
        "@absl_git//absl/testing:absltest",
    ],
)

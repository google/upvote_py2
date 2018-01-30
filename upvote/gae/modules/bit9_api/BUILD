load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        ":change_set",
        ":handlers",
        ":monitoring",
        ":sync",
        ":utils",
    ],
)

py_appengine_library(
    name = "sync",
    srcs = ["sync.py"],
    deps = [
        ":change_set",
        ":constants",
        ":rest_utils",
        ":monitoring",
        ":utils",
        "//common:datastore_locks",
        "//common:memcache_decorator",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/binary_health:metrics",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:intermodule",
        "//upvote/gae/shared/common:query_utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:taskqueue_utils",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bigquery",
        "//upvote/gae/shared/models:bit9",
        "//upvote/shared:constants",
        "//upvote/shared:time_utils",
    ],
)

py_appengine_library(
    name = "handlers",
    srcs = ["handlers.py"],
    deps = [
        ":change_set",
        ":constants",
        ":rest_utils",
        ":monitoring",
        ":utils",
        "//common:memcache_decorator",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:intermodule",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
        "//upvote/shared:constants",
        "//upvote/shared:time_utils",
    ],
)

py_appengine_library(
    name = "change_set",
    srcs = ["change_set.py"],
    deps = [
        ":constants",
        ":utils",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/models:bit9",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "cron",
    srcs = ["cron.py"],
    deps = [
        ":change_set",
        ":constants",
        ":rest_utils",
        ":monitoring",
        ":sync",
        ":utils",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:query_utils",
        "//upvote/gae/shared/common:taskqueue_utils",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/shared/common:monitoring",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    deps = [
        "//common:context",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/models:bit9",
    ],
)

py_appengine_library(
    name = "routes",
    srcs = ["routes.py"],
    deps = [
        ":cron",
        ":handlers",
        ":monitoring",
        ":sync",
        "//upvote/gae/shared/common:handlers",
    ],
)

py_library(
    name = "constants",
    srcs = ["constants.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "rest_utils",
    srcs = ["rest_utils.py"],
    deps = [
        ":constants",
        "//upvote/gae/shared/common:settings",
    ],
)

py_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        ":constants",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/common:settings",
    ],
)

py_appengine_library(
    name = "bit9_api_library",
    data = [
        "//upvote/gae:bit9_api.yaml",
    ],
    deps = [
        ":cron",
        ":handlers",
        ":routes",
        ":monitoring",
        "//upvote/gae/shared/common:handlers",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "sync_test",
    srcs = ["sync_test.py"],
    deps = [
        ":constants",
        ":sync",
        ":test_utils",
        "//common:datastore_locks",
        "//external:mock",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:test_utils",
        "//upvote/gae/shared/models:bit9",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "handlers_test",
    size = "small",
    srcs = ["handlers_test.py"],
    deps = [
        ":constants",
        ":handlers",
        "//external:mock",
        "//external:webtest",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
        "//upvote/gae/shared/models:test_utils",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "change_set_test",
    srcs = ["change_set_test.py"],
    deps = [
        ":change_set",
        ":utils",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/models:bit9",
        "//upvote/gae/shared/models:test_utils",
    ],
)

upvote_appengine_test(
    name = "cron_test",
    srcs = ["cron_test.py"],
    deps = [
        ":cron",
        ":monitoring",
        ":sync",
        "//upvote/gae/modules/bit9_api/api",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:utils",
        "//upvote/gae/shared/models:base",
        "//upvote/gae/shared/models:bit9",
    ],
)

upvote_appengine_test(
    name = "monitoring_test",
    size = "small",
    srcs = ["monitoring_test.py"],
    deps = [
        ":monitoring",
        "//common/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "rest_utils_test",
    size = "small",
    srcs = ["rest_utils_test.py"],
    deps = [
        ":constants",
        ":rest_utils",
        "//upvote/gae/shared/common:settings",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/models:test_utils",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "routes_test",
    size = "small",
    srcs = ["routes_test.py"],
    deps = [
        ":bit9_api_library",
        "//upvote/gae/shared/common:basetest",
    ],
)

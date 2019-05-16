load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "api",
    srcs = ["api.py"],
    deps = [
        ":constants",
        ":context",
        ":exceptions",
        ":model",
    ],
)

py_library(
    name = "constants",
    srcs = ["constants.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//upvote/shared:constants",
    ],
)

py_library(
    name = "context",
    srcs = ["context.py"],
    deps = [
        ":constants",
        ":exceptions",
        "//external:requests",
        "//external:six",
        "@absl_git//absl:app",
    ],
)

py_library(
    name = "exceptions",
    srcs = ["exceptions.py"],
    srcs_version = "PY2AND3",
)

py_library(
    name = "query",
    srcs = ["query.py"],
    deps = [
        ":constants",
        ":exceptions",
        ":query_nodes",
        "@absl_git//absl:app",
    ],
)

py_library(
    name = "query_nodes",
    srcs = ["query_nodes.py"],
    deps = [
        ":exceptions",
    ],
)

py_library(
    name = "model",
    srcs = ["model.py"],
    deps = [
        ":constants",
        ":exceptions",
        ":query",
        ":query_nodes",
        "@absl_git//absl:app",
    ],
)

py_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        ":api",
        ":constants",
        "//external:mock",
        "//external:requests",
        "//upvote/gae:settings",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "change_set",
    srcs = ["change_set.py"],
    deps = [
        ":api",
        ":constants",
        ":monitoring",
        ":utils",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:cert",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/utils:monitoring_utils",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
    deps = [
        ":api",
        ":constants",
        "//common:context",
        "//upvote/gae:settings",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/utils:env_utils",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "context_test",
    size = "small",
    srcs = ["context_test.py"],
    deps = [
        ":context",
        ":exceptions",
        ":test_utils",
        "//external:mock",
        "//external:requests",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "model_test",
    size = "small",
    srcs = ["model_test.py"],
    deps = [
        ":context",
        ":exceptions",
        ":model",
        ":test_utils",
        "//external:mock",
        "//external:requests",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "query_test",
    size = "small",
    srcs = ["query_test.py"],
    deps = [
        ":context",
        ":exceptions",
        ":model",
        ":query",
        ":test_utils",
        "//external:mock",
        "//external:requests",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "change_set_test",
    srcs = ["change_set_test.py"],
    data = [":fake_credentials"],
    deps = [
        ":change_set",
        ":utils",
        "//common:context",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:rule",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:bit9test",
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
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "//upvote/gae:settings",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

# Test Data
# ==============================================================================

filegroup(
    name = "fake_credentials",
    srcs = ["fake_credentials.json"],
)

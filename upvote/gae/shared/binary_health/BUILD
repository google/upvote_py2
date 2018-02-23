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
        ":binary_health",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "binary_health",
    srcs = ["binary_health.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/shared/binary_health/virustotal:virustotal_client",
    ],
)

py_appengine_library(
    name = "metrics",
    srcs = ["metrics.py"],
    deps = [
        ":binary_health",
        ":monitoring",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:metrics",
        "//upvote/gae/shared/binary_health/virustotal:constants",
        "//upvote/gae/shared/common:settings",
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

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "binary_health_test",
    size = "small",
    srcs = ["binary_health_test.py"],
    deps = [
        ":binary_health",
        "//external:mock",
        "//external:webtest",
        "//upvote/gae/shared/common:basetest",
    ],
)

upvote_appengine_test(
    name = "metrics_test",
    size = "small",
    srcs = ["metrics_test.py"],
    deps = [
        ":metrics",
        "//external:mock",
        "//external:webtest",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "monitoring_test",
    size = "small",
    srcs = ["monitoring_test.py"],
    deps = [
        ":binary_health",
        ":monitoring",
        "//common/testing:basetest",
    ],
)

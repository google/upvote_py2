load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "api",
    srcs = ["api.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/lib/analysis/virustotal:virustotal_client",
    ],
)

py_appengine_library(
    name = "metrics",
    srcs = ["metrics.py"],
    deps = [
        ":api",
        ":monitoring",
        "//upvote/gae:settings",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:metrics",
        "//upvote/gae/datastore/models:package",
        "//upvote/gae/lib/analysis/virustotal:constants",
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

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "api_test",
    size = "small",
    srcs = ["api_test.py"],
    deps = [
        ":api",
        "//external:mock",
        "//external:webtest",
        "//upvote/gae/lib/testing:basetest",
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
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "monitoring_test",
    size = "small",
    srcs = ["monitoring_test.py"],
    deps = [
        ":api",
        ":monitoring",
        "//common/testing:basetest",
    ],
)

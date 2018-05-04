load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "analysis",
    srcs = ["analysis.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/lib/analysis/virustotal:virustotal_client",
    ],
)

py_appengine_library(
    name = "metrics",
    srcs = ["metrics.py"],
    deps = [
        ":analysis",
        ":monitoring",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:metrics",
        "//upvote/gae/lib/analysis/virustotal:constants",
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
    name = "analysis_test",
    size = "small",
    srcs = ["analysis_test.py"],
    deps = [
        ":analysis",
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
        ":analysis",
        ":monitoring",
        "//common/testing:basetest",
    ],
)

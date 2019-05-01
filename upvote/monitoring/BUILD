package(default_visibility = ["//upvote"])

package_group(
    name = "monitoring",
    packages = [
        "//upvote/monitoring/...",
    ],
)

# Libraries
# ==============================================================================

py_library(
    name = "metrics",
    srcs = ["metrics.py"],
    srcs_version = "PY2AND3",
    deps = [],
)

# Unit Tests
# ==============================================================================

py_test(
    name = "metrics_test",
    srcs = ["metrics_test.py"],
    deps = [
        ":metrics",
        "@absl_git//absl/testing:absltest",
    ],
)

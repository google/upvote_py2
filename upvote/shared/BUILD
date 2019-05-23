package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "constants",
    srcs = ["constants.py"],
    srcs_version = "PY2AND3",
)

# Unit Tests
# ==============================================================================

py_test(
    name = "constants_test",
    size = "small",
    srcs = ["constants_test.py"],
    deps = [
        ":constants",
        "//external:six",
        "@absl_git//absl/testing:absltest",
    ],
)

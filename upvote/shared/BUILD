package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "constants",
    srcs = ["constants.py"],
)

# Unit Tests
# ==============================================================================

py_test(
    name = "constants_test",
    size = "small",
    srcs = ["constants_test.py"],
    deps = [
        ":constants",
        "@absl_git//absl/testing:absltest",
    ],
)

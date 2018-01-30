package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "constants",
    srcs = ["constants.py"],
)

py_library(
    name = "time_utils",
    srcs = ["time_utils.py"],
    deps = [
        "//upvote/gae/modules/bit9_api:constants",
    ],
)

py_library(
    name = "utils",
    srcs = ["utils.py"],
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

py_test(
    name = "time_utils_test",
    size = "small",
    srcs = ["time_utils_test.py"],
    deps = [
        ":time_utils",
        "//external:mock",
        "@absl_git//absl/testing:absltest",
    ],
)

py_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "@absl_git//absl/testing:absltest",
    ],
)

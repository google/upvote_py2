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
)

py_library(
    name = "context",
    srcs = ["context.py"],
    deps = [
        ":constants",
        ":exceptions",
        ":utils",
        "//external:requests",
        "//external:six",
        "@absl_git//absl:app",
    ],
)

py_library(
    name = "exceptions",
    srcs = ["exceptions.py"],
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
        "//external:mock",
        "//external:requests",
    ],
)

py_library(
    name = "utils",
    srcs = ["utils.py"],
)

# Unit Tests
# ==============================================================================

py_test(
    name = "api_test",
    size = "small",
    srcs = ["api_test.py"],
    deps = [
        ":api",
        "//external:mock",
        "@absl_git//absl/testing:absltest",
    ],
)

py_test(
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

py_test(
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

py_test(
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

py_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "@absl_git//absl/testing:absltest",
    ],
)

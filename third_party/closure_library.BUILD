package(default_visibility = ["//visibility:public"])

licenses(["notice"]) # Apache2

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_library")

closure_js_library(
    name = "base",
    srcs = [
        "closure/goog/transpile.js",
        "closure/goog/base.js",
        "closure/goog/deps.js",
    ],
)

closure_js_library(
    name = "math_long",
    srcs = ["closure/goog/math/long.js"],
    deps = [
        ":asserts",
        ":reflect",
        ":base",
    ],
)

closure_js_library(
    name = "math",
    srcs = ["closure/goog/math/math.js"],
    deps = [
        ":asserts",
        ":array",
        ":reflect",
        ":base",
    ],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "reflect",
    srcs = ["closure/goog/reflect/reflect.js"],
    deps = [":base"],
)

closure_js_library(
    name = "array",
    srcs = ["closure/goog/array/array.js"],
    deps = [":base", ":asserts"],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "jsunit",
    testonly = True,
    srcs = [
        "closure/goog/testing/jsunit.js",
        "closure/goog/testing/testcase.js",
        "closure/goog/testing/asserts.js",
        "closure/goog/testing/testrunner.js",
        "closure/goog/testing/jsunitexception.js"],
    deps = [":base", ":asserts", ":object"],
    suppress = [
        "lintChecks",
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "uri",
    srcs = [
        "closure/goog/uri/uri.js",
        "closure/goog/uri/utils.js",
    ],
    deps = [":base", ":array", ":asserts", ":string", ":structs"],
    suppress = [
        "analyzerChecks",
        "deprecated",    "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "asserts",
    srcs = ["closure/goog/asserts/asserts.js"],
    deps = [
        ":debug_error",
        ":dom_nodetype",
        ":string",
        ":base",
    ],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "iter",
    srcs = ["closure/goog/iter/iter.js"],
    deps = [
        ":base",
        ":array",
        ":asserts",
        ":functions",
        ":math",
    ],
    suppress = [
        "analyzerChecks",
        "JSC_MUST_BE_PRIVATE",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "functions",
    srcs = ["closure/goog/functions/functions.js"],
    deps = [
        ":base",
        ":array",
        ":asserts",
        ":math_long",
    ],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "object",
    srcs = ["closure/goog/object/object.js"],
    deps = [
        ":base",
    ],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

closure_js_library(
    name = "structs",
    srcs = ["closure/goog/structs/map.js", "closure/goog/structs/structs.js"],
    deps = [
        ":base",
        ":array",
        ":iter",
        ":object",
    ],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
        "JSC_MUST_BE_PRIVATE",
    ],
)

closure_js_library(
    name = "debug_error",
    srcs = ["closure/goog/debug/error.js"],
    deps = [":base"],
)

closure_js_library(
    name = "dom_nodetype",
    srcs = ["closure/goog/dom/nodetype.js"],
    deps = [":base"],
)

closure_js_library(
    name = "string",
    srcs = ["closure/goog/string/string.js"],
    deps = [":base"],
    suppress = [
        "analyzerChecks",
        "reportUnknownTypes",
    ],
)

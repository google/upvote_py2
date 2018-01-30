licenses(["notice"])  # MIT

py_library(
    name = "webtest",
    srcs = glob(["webtest/*.py"]),
    srcs_version = "PY2AND3",
    visibility = ["//visibility:public"],
    deps = [
        "//external:six",
        "//external:waitress",
        "//external:beautifulsoup4",
    ],
)
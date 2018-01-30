licenses(["notice"])  # Apache v2.0

py_library(
    name = "requests",
    srcs = glob(["requests/**"]),
    srcs_version = "PY2AND3",
    visibility = ["//visibility:public"],
    deps = [
        "//external:chardet",
        "//external:idna",
        "//external:urllib3",
        "//external:certifi",
    ],
)

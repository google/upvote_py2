licenses(["notice"])  # Apache v2.0

py_library(
    name = "gcloud_auth",
    srcs = glob(["google/**"]),
    srcs_version = "PY2AND3",
    visibility = ["//visibility:public"],
    deps = [
        "//external:pyasn1",
        "//external:pyasn1_modules",
        "//external:rsa",
        "//external:six",
        "//external:cachetools",
    ],
)

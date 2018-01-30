licenses(["notice"])  # BSD

py_library(
    name = "protobuf",
    srcs = glob(
        include=[
            "google/**"
        ],
        exclude=[
            "google/protobuf/pyext/**",
            "google/protobuf/internal/*.cc",
            "google/protobuf/*.h",
    ]),
    srcs_version = "PY2AND3",
    visibility = ["//visibility:public"],
    deps = [
        "//external:six",
    ],
)

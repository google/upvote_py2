licenses(["notice"])  # Apache v2.0

py_library(
    name = "gcloud_core",
    srcs = glob(["google/**"]),
    srcs_version = "PY2AND3",
    # Include the .egg-info in order to make the package discoverable to
    # python. This is necessary because the library dynamically sets its
    # '__version__' property from the detected package installation's version.
    data = glob(["*.egg-info/**"]),
    visibility = ["//visibility:public"],
    deps = [
        "//external:httplib2",
        "//external:gapi_protos",
        "//external:protobuf",
        "//external:gcloud_auth",
        "//external:gcloud_auth_httplib2",
        "//external:six",
    ],
)

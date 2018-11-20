package(default_visibility = ["//upvote"])

py_library(
    name = "fake_monotonic",
    srcs = ["fake_monotonic.py"],
)

py_library(
    name = "google_cloud_lib_fixer",
    srcs = ["google_cloud_lib_fixer.py"],
    deps = [
        ":fake_monotonic",
        "//external:requests_toolbelt",
    ],
)

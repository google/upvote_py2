package(default_visibility = ["//visibility:public"])

load("//upvote:builddefs.bzl", "upvote_appengine_test")

py_library(
    name = "cloud_kms",
    srcs = ["cloud_kms.py"],
    deprecation = "Please use google-cloud-kms library.",
    deps = [
        "//external:googleapiclient",
        "//external:httplib2",
        "//external:oauth2client",
    ],
)

package(default_visibility = ["//visibility:public"])

load("//upvote:builddefs.bzl", "upvote_appengine_test")

# To keep build_cleaner happy.
py_library(
    name = "__init__",
    srcs = ["__init__.py"],
)

py_library(
    name = "cloud_kms",
    srcs = ["cloud_kms.py"],
    deps = [
        "//external:googleapiclient",
        "//external:httplib2",
        "//external:oauth2client",
    ],
)

py_library(
    name = "kms_ndb",
    srcs = [
        "kms_ndb.py",
    ],
    deps = [":cloud_kms"],
)

upvote_appengine_test(
    name = "kms_ndb_test",
    size = "small",
    srcs = ["kms_ndb_test.py"],
    deps = [
        ":cloud_kms",
        ":kms_ndb",
        "//common/testing:basetest",
        "//external:mock",
    ],
)

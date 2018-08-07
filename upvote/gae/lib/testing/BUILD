load("//upvote:builddefs.bzl", "py_appengine_library")

package(default_visibility = ["//upvote"])

py_appengine_library(
    name = "basetest",
    testonly = 1,
    srcs = ["basetest.py"],
    data = ["//upvote/gae:index.yaml"],
    deps = [
        "//common/testing:basetest",
        "//external:mock",
        "//external:oauth2client",
        "//external:webob",
        "//external:webtest",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:settings_utils",
        "//upvote/gae/utils:xsrf_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        "//external:mock",
    ],
)

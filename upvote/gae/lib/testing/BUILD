load("//upvote:builddefs.bzl", "py_appengine_library")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "basetest",
    testonly = 1,
    srcs = ["basetest.py"],
    data = ["//upvote/gae:index.yaml"],
    deps = [
        "//common/testing:basetest",
        "//external:mock",
        "//external:oauth2client",
        "//external:six",
        "//external:webob",
        "//external:webtest",
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:handler_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "bit9test",
    testonly = 1,
    srcs = ["bit9test.py"],
    deps = [
        ":basetest",
        "//external:mock",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/lib/bit9:utils",
    ],
)

py_appengine_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//external:mock",
        "//external:six",
    ],
)

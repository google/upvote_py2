load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

py_appengine_library(
    name = "constants",
    srcs = ["constants.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "virustotal_client",
    srcs = ["virustotal_client.py"],
    deps = [
        ":constants",
        "//upvote/gae/datastore/models:virustotal",
        "//upvote/gae/shared/common:memcache_utils",
    ],
)

upvote_appengine_test(
    name = "virustotal_client_test",
    size = "small",
    srcs = ["virustotal_client_test.py"],
    deps = [
        ":virustotal_client",
        "//common/testing:basetest",
        "//external:mock",
        "@absl_git//absl/testing:absltest",
    ],
)

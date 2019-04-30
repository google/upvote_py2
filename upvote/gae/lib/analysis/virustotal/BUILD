load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "constants",
    srcs = ["constants.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//upvote/shared:constants",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "virustotal_client",
    srcs = ["virustotal_client.py"],
    deps = [
        ":constants",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/gae/utils:memcache_utils",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

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

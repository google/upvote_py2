package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "tables",
    srcs = ["tables.py"],
    deps = [
        ":monitoring",
        "//external:gcloud_bigquery",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/shared/common:monitoring",
        "//upvote/monitoring:metrics",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "tables_test",
    size = "small",
    srcs = ["tables_test.py"],
    deps = [
        ":tables",
        "//external:mock",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

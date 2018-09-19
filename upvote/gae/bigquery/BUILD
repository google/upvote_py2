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
        "//external:gcloud_auth",
        "//external:gcloud_bigquery",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
        "//upvote/gae/shared/common:settings",
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
        "//external:gcloud_bigquery",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

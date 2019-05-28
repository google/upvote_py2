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
        "//external:six",
        "//upvote/gae/lib/cloud:google_cloud_lib_fixer",
        "//upvote/gae/utils:env_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/utils:monitoring_utils",
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
        "//external:six",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

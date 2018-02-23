load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "all",
    deps = [
        ":voting",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "voting",
    srcs = ["voting.py"],
    deps = [
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/shared/binary_health:metrics",
        "//upvote/gae/shared/common:intermodule",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:taskqueue_utils",
        "//upvote/gae/shared/common:user_map",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "bigquery_schema",
    srcs = ["bigquery_schema.py"],
    deps = [
        "//external:gcloud_bigquery",
        "//upvote/gae/shared/common:google_cloud_lib_fixer",
        "//upvote/shared:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "voting_test",
    size = "medium",
    srcs = ["voting_test.py"],
    deps = [
        ":voting",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:base",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "bigquery_schema_test",
    size = "medium",
    srcs = ["bigquery_schema_test.py"],
    deps = [
        ":bigquery_schema",
        "//upvote/gae/datastore/models:bigquery",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
    ],
)

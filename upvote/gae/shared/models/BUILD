load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        ":base",
        ":bigquery",
        ":bit9",
        ":santa",
    ],
)

py_appengine_library(
    name = "base",
    srcs = ["base.py"],
    deps = [
        ":bigquery",
        ":utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:taskqueue_utils",
        "//upvote/gae/shared/common:user_map",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "bigquery",
    srcs = ["bigquery.py"],
    deps = [
        "//upvote/gae/shared/common:monitoring",
        "//upvote/gae/shared/common:settings",
        "//upvote/monitoring:metrics",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "bit9",
    srcs = ["bit9.py"],
    deps = [
        ":base",
        ":utils",
        "//common/cloud_kms:kms_ndb",
        "//upvote/gae/shared/models:bigquery",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "cache",
    srcs = ["cache.py"],
)

py_appengine_library(
    name = "metrics",
    srcs = ["metrics.py"],
    deps = [
        "//upvote/gae/shared/binary_health/virustotal:constants",
    ],
)

py_appengine_library(
    name = "santa",
    srcs = ["santa.py"],
    deps = [
        ":base",
        ":bigquery",
        "//upvote/gae/shared/common:query_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "test_utils",
    srcs = ["test_utils.py"],
    deps = [
        ":base",
        ":bit9",
        ":santa",
        "//external:mock",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "tickets",
    srcs = ["tickets.py"],
    deps = [
        ":base",
    ],
)

py_appengine_library(
    name = "utils",
    srcs = ["utils.py"],
)

py_appengine_library(
    name = "virustotal",
    srcs = ["virustotal.py"],
    deps = [
        ":utils",
        "//common/cloud_kms:kms_ndb",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "base_test",
    size = "small",
    srcs = ["base_test.py"],
    deps = [
        ":base",
        ":bigquery",
        ":test_utils",
        ":utils",
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:utils",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "bigquery_test",
    size = "small",
    srcs = ["bigquery_test.py"],
    deps = [
        ":bigquery",
        ":test_utils",
        ":utils",
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "bit9_test",
    size = "small",
    srcs = ["bit9_test.py"],
    deps = [
        ":bit9",
        ":test_utils",
        ":utils",
        "//common/testing:basetest",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "santa_test",
    size = "small",
    srcs = ["santa_test.py"],
    deps = [
        ":santa",
        ":test_utils",
        ":utils",
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/shared/common:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "tickets_test",
    size = "small",
    srcs = ["tickets_test.py"],
    deps = [
        ":tickets",
        "//common/testing:basetest",
        "//upvote/gae/shared/common:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "utils_test",
    size = "small",
    srcs = ["utils_test.py"],
    deps = [
        ":utils",
        "//common/testing:basetest",
        "//external:mock",
        "@absl_git//absl/testing:absltest",
    ],
)

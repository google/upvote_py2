package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "all",
    deps = [
        ":alert",
        ":base",
        ":bit9",
        ":cache",
        ":metrics",
        ":mixin",
        ":rule",
        ":santa",
        ":singleton",
        ":tickets",
        ":virustotal",
    ],
)

py_appengine_library(
    name = "alert",
    srcs = ["alert.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "base",
    srcs = ["base.py"],
    deps = [
        ":mixin",
        ":user",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "bit9",
    srcs = ["bit9.py"],
    deps = [
        ":base",
        ":mixin",
        "//common/cloud_kms:kms_ndb",
        "//upvote/gae/datastore/models:singleton",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "cache",
    srcs = ["cache.py"],
)

py_appengine_library(
    name = "exemption",
    srcs = ["exemption.py"],
    deps = [
        ":base",
        ":mixin",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/taskqueue:utils",
    ],
)

py_appengine_library(
    name = "metrics",
    srcs = ["metrics.py"],
    deps = [
        "//upvote/gae/lib/analysis/virustotal:constants",
    ],
)

py_appengine_library(
    name = "mixin",
    srcs = ["mixin.py"],
    deps = [
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "rule",
    srcs = ["rule.py"],
    deps = [
        ":santa",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "santa",
    srcs = ["santa.py"],
    deps = [
        ":base",
        ":mixin",
        ":user",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "singleton",
    srcs = ["singleton.py"],
    deps = [],
)

py_appengine_library(
    name = "tickets",
    srcs = ["tickets.py"],
    deps = [
        ":mixin",
    ],
)

py_appengine_library(
    name = "user",
    srcs = ["user.py"],
    deps = [
        ":mixin",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/shared/common:settings",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/taskqueue:utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "virustotal",
    srcs = ["virustotal.py"],
    deps = [
        "//common/cloud_kms:kms_ndb",
        "//upvote/gae/datastore/models:singleton",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "alert_test",
    size = "small",
    srcs = ["alert_test.py"],
    deps = [
        ":alert",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "base_test",
    size = "small",
    srcs = ["base_test.py"],
    deps = [
        ":base",
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:settings",
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
        "//common/testing:basetest",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "exemption_test",
    size = "small",
    srcs = ["exemption_test.py"],
    deps = [
        ":base",
        ":exemption",
        "//common/testing:basetest",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "mixin_test",
    size = "small",
    srcs = ["mixin_test.py"],
    deps = [
        ":mixin",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "rule_test",
    size = "small",
    srcs = ["rule_test.py"],
    deps = [
        ":rule",
        ":santa",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
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
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "singleton_test",
    size = "small",
    srcs = ["singleton_test.py"],
    deps = [
        ":singleton",
        "//external:mock",
        "//upvote/gae/lib/testing:basetest",
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
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "user_test",
    size = "small",
    srcs = ["user_test.py"],
    deps = [
        ":user",
        "//common/testing:basetest",
        "//external:mock",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/shared/common:settings",
        "//upvote/shared:constants",
        "@absl_git//absl/testing:absltest",
    ],
)

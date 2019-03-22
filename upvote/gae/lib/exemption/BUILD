load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_test",
)

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "api",
    srcs = ["api.py"],
    deps = [
        ":checks",
        ":monitoring",
        ":notify",
        "//external:futures",
        "//upvote/gae:settings",
        "//upvote/gae/bigquery:tables",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:policy",
        "//upvote/gae/lib/bit9:api",
        "//upvote/gae/lib/bit9:utils",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:mail_utils",
        "//upvote/gae/utils:template_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "checks",
    srcs = ["checks.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:utils",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:group_utils",
        "//upvote/gae/utils:user_utils",
        "//upvote/shared:constants",
    ],
)

py_appengine_library(
    name = "notify",
    srcs = ["notify.py"],
    deps = [
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/utils:env_utils",
        "//upvote/gae/utils:mail_utils",
        "//upvote/gae/utils:template_utils",
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
    name = "api_test",
    size = "small",
    srcs = ["api_test.py"],
    data = ["//upvote/gae/lib/bit9:fake_credentials"],
    deps = [
        ":api",
        ":checks",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore/models:exemption",
        "//upvote/gae/datastore/models:host",
        "//upvote/gae/datastore/models:policy",
        "//upvote/gae/datastore/models:santa",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/gae/lib/testing:bit9test",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "notify_test",
    size = "small",
    srcs = ["notify_test.py"],
    deps = [
        ":notify",
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

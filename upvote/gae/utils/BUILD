load("//upvote:builddefs.bzl", "py_appengine_library", "upvote_appengine_test")

package(default_visibility = ["//upvote"])

# Libraries
# ==============================================================================

py_library(
    name = "iter_utils",
    srcs = ["iter_utils.py"],
    srcs_version = "PY2AND3",
    deps = ["//external:six"],
)

py_library(
    name = "string_utils",
    srcs = ["string_utils.py"],
    srcs_version = "PY2AND3",
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "env_utils",
    srcs = ["env_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//common:context",
        "//external:six",
    ],
)

py_appengine_library(
    name = "handler_utils",
    srcs = ["handler_utils.py"],
    deps = [
        ":env_utils",
        ":json_utils",
        ":string_utils",
        ":xsrf_utils",
        "//external:six",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:user",
    ],
)

py_appengine_library(
    name = "json_utils",
    srcs = ["json_utils.py"],
    srcs_version = "PY2AND3",
    deps = ["//external:six"],
)

py_appengine_library(
    name = "mail_utils",
    srcs = ["mail_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        ":env_utils",
        ":user_utils",
    ],
)

py_appengine_library(
    name = "memcache_utils",
    srcs = ["memcache_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//common:memcache_decorator",
    ],
)

py_appengine_library(
    name = "monitoring_utils",
    srcs = ["monitoring_utils.py"],
)

py_appengine_library(
    name = "template_utils",
    srcs = ["template_utils.py"],
    data = [
        "//upvote/gae/templates/email:templates",
        "//upvote/gae/templates/web:templates",
    ],
    srcs_version = "PY2AND3",
)

py_appengine_library(
    name = "time_utils",
    srcs = ["time_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//upvote/gae/lib/bit9:constants",
    ],
)

py_library(
    name = "user_utils",
    srcs = ["user_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//upvote/gae:settings",
    ],
)

py_appengine_library(
    name = "xsrf_utils",
    srcs = ["xsrf_utils.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//external:oauth2client",
        "//upvote/gae/datastore/models:singleton",
    ],
)

py_appengine_library(
    name = "group_utils",
    srcs = ["group_utils.py"],
)

# Unit Tests
# ==============================================================================

py_test(
    name = "iter_utils_test",
    size = "small",
    srcs = ["iter_utils_test.py"],
    deps = [
        ":iter_utils",
        "@absl_git//absl/testing:absltest",
    ],
)

py_test(
    name = "string_utils_test",
    size = "small",
    srcs = ["string_utils_test.py"],
    deps = [
        ":string_utils",
        "@absl_git//absl/testing:absltest",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "env_utils_test",
    size = "small",
    srcs = ["env_utils_test.py"],
    deps = [
        ":env_utils",
        "//upvote/gae:settings",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "handler_utils_test",
    size = "small",
    srcs = ["handler_utils_test.py"],
    deps = [
        ":handler_utils",
        "//common/testing:basetest",
        "//external:mock",
        "//external:webob",
        "//external:webtest",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "json_utils_test",
    size = "small",
    srcs = ["json_utils_test.py"],
    deps = [
        ":json_utils",
        "//common/testing:basetest",
        "//external:six",
        "//upvote/gae/datastore/models:binary",
        "//upvote/gae/datastore/models:event",
        "//upvote/shared:constants",
    ],
)

upvote_appengine_test(
    name = "mail_utils_test",
    size = "small",
    srcs = ["mail_utils_test.py"],
    deps = [
        ":mail_utils",
        ":user_utils",
        "//external:mock",
        "//upvote/gae:settings",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "memcache_utils_test",
    size = "small",
    srcs = ["memcache_utils_test.py"],
    deps = [
        ":memcache_utils",
        "//common/testing:basetest",
        "//external:mock",
    ],
)

upvote_appengine_test(
    name = "template_utils_test",
    size = "small",
    srcs = ["template_utils_test.py"],
    data = ["//upvote/gae/templates/test:templates"],
    deps = [
        ":template_utils",
        "//common/testing:basetest",
        "//external:six",
    ],
)

upvote_appengine_test(
    name = "time_utils_test",
    size = "small",
    srcs = ["time_utils_test.py"],
    deps = [
        ":time_utils",
        "//external:mock",
        "//external:six",
        "@absl_git//absl/testing:absltest",
    ],
)

upvote_appengine_test(
    name = "user_utils_test",
    size = "small",
    srcs = ["user_utils_test.py"],
    deps = [
        ":user_utils",
        "//upvote/gae/lib/testing:basetest",
    ],
)

upvote_appengine_test(
    name = "xsrf_utils_test",
    size = "small",
    srcs = ["xsrf_utils_test.py"],
    deps = [
        ":xsrf_utils",
        "//external:mock",
        "//external:oauth2client",
        "//upvote/gae/lib/testing:basetest",
        "@absl_git//absl/testing:absltest",
    ],
)

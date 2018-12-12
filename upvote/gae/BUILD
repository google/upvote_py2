package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "upvote_appengine_binary",
    "py_appengine_library",
    "upvote_appengine_test",
)

exports_files(glob(["*.yaml"]))

# Binaries
# ==============================================================================

upvote_appengine_binary(
    name = "monolith_binary",
    srcs = ["appengine_config.py"],
    configs = glob(["*.yaml"]) + [":appengine_config.py"],
    data = [
        "//upvote/gae/shared/templates",
    ],
    deps = [
        "//upvote/gae/datastore:all",
        "//upvote/gae/modules/santa_api:santa_api_library",
        "//upvote/gae/modules/upvote_app:upvote_app_library",
        "//upvote/gae/shared:all",
    ],
)

# MPMs
# ==============================================================================

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "appengine_config",
    srcs = ["appengine_config.py"],
    deps = [
        ":settings",
        "//upvote/gae/datastore/models:rule",
    ],
)

py_appengine_library(
    name = "settings",
    srcs = ["settings.py"],
    deps = [
        "//common:context",
        "//upvote/gae/utils:settings_utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "appengine_config_test",
    size = "small",
    srcs = ["appengine_config_test.py"],
    deps = [
        ":appengine_config",
        ":settings",
        "//upvote/gae/lib/testing:basetest",
        "//upvote/shared:constants",
    ],
)

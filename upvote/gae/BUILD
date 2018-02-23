package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "py_appengine_binary",
    "py_appengine_library",
    "upvote_appengine_test",
)

exports_files(glob(["*.yaml"]))

# Binaries
# ==============================================================================

py_appengine_binary(
    name = "monolith_binary",
    srcs = ["appengine_config.py"],
    configs = glob(["*.yaml"]) + [":appengine_config.py"],
    data = [
        "//upvote/gae/shared/templates",
    ],
    deps = [
        ":appengine_config_utils",
        "//upvote/gae/datastore:all",
        "//upvote/gae/modules/bit9_api:bit9_api_library",
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
    name = "appengine_config_utils",
    srcs = ["appengine_config_utils.py"],
    deps = [
        "//upvote/gae/datastore:test_utils",
        "//upvote/gae/datastore:utils",
        "//upvote/gae/datastore/models:all",
        "//upvote/gae/shared/common:user_map",
        "//upvote/gae/shared/common:utils",
        "//upvote/shared:constants",
    ],
)

# AppEngine Unit Tests
# ==============================================================================

upvote_appengine_test(
    name = "appengine_config_utils_test",
    size = "small",
    srcs = ["appengine_config_utils_test.py"],
    deps = [
        ":appengine_config_utils",
        "//upvote/gae/datastore/models:all",
        "//upvote/gae/shared/common:basetest",
    ],
)

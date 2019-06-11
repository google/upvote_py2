package(default_visibility = ["//upvote"])

load(
    "//upvote:builddefs.bzl",
    "py_appengine_library",
    "upvote_appengine_binary",
)

exports_files(glob(["*.yaml"]))

# Binaries
# ==============================================================================

upvote_appengine_binary(
    name = "monolith_binary",
    srcs = ["appengine_config.py"],
    configs = glob(["*.yaml"]) + [":appengine_config.py"],
    deps = [
        "//upvote/gae/datastore:all",
        "//upvote/gae/modules/upvote_app:upvote_app_library",
        "//upvote/gae/shared:all",
    ],
)

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "appengine_config",
    srcs = ["appengine_config.py"],
    deps = [
        ":settings",
        "//common/monitoring",
        "//upvote/gae/datastore/models:utils",
    ],
)

py_appengine_library(
    name = "settings",
    srcs = ["settings.py"],
    srcs_version = "PY2AND3",
    deps = [
        "//upvote/gae/utils:env_utils",
        "//upvote/shared:constants",
    ],
)

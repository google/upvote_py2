package(default_visibility = ["//upvote"])

load("//upvote:builddefs.bzl", "py_appengine_library", "py_appengine_binary")

py_appengine_library(
    name = "upvote_app_library",
    data = [
        "//upvote/gae:app.yaml",
        "//upvote/gae/modules/upvote_app/frontend:app_css",
        "//upvote/gae/modules/upvote_app/frontend:app_min",
        "//upvote/gae/shared/templates",
    ],
    deps = [
        "//upvote/gae/modules/upvote_app/api",
    ],
)

py_appengine_binary(
    name = "upvote_app_binary",
    srcs = ["//upvote/gae/modules/upvote_app/api:main.py"],
    configs = [
        "//upvote/gae:app.yaml",
        "//upvote/gae:appengine_config.py",
    ],
    deps = [
        ":upvote_app_library",
    ],
)

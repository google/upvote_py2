package(default_visibility = ["//upvote"])

load("//upvote:builddefs.bzl", "py_appengine_binary")

exports_files(glob(["*.yaml"]))

py_appengine_binary(
    name = "monolith_binary",
    srcs = ["appengine_config.py"],
    configs = glob(["*.yaml"]) + [":appengine_config.py"],
    data = [
        "//upvote/gae/shared/templates",
    ],
    deps = [
        "//upvote/gae/modules/bit9_api:bit9_api_library",
        "//upvote/gae/modules/santa_api:santa_api_library",
        "//upvote/gae/modules/upvote_app:upvote_app_library",
        "//upvote/gae/shared:all",
    ],
)

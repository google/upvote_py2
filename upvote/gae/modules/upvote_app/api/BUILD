load("//upvote:builddefs.bzl", "py_appengine_library")

package(default_visibility = ["//upvote"])

# AppEngine Libraries
# ==============================================================================

py_appengine_library(
    name = "monitoring",
    srcs = ["monitoring.py"],
    deps = [
        "//upvote/gae/shared/common:monitoring",
        "//upvote/monitoring:metrics",
    ],
)

py_appengine_library(
    name = "api",
    srcs = ["main.py"],
    deps = [
        ":monitoring",
        "//upvote/gae/modules/upvote_app/api/handlers:all_srcs",
        "//upvote/gae/modules/upvote_app/cron:all",
        "//upvote/gae/shared/common:handlers",
        "//upvote/gae/shared/common:settings",
    ],
)

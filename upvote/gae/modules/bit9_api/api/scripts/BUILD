package(default_visibility = ["//upvote"])

py_binary(
    name = "build_from_docs",
    srcs = ["build_from_docs.py"],
    deps = [
        "//upvote/gae/modules/bit9_api/api:utils",
        "@absl_git//absl:app",
        "@beautifulsoup4_archive//:beautifulsoup4",
    ],
)

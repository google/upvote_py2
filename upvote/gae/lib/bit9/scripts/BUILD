package(default_visibility = ["//upvote"])

py_binary(
    name = "build_from_docs",
    srcs = ["build_from_docs.py"],
    python_version = "PY2",
    deps = [
        "//external:six",
        "//upvote/gae/lib/bit9:utils",
        "@beautifulsoup4_archive//:beautifulsoup4",
    ],
)

package(default_visibility = ["//visibility:public"])

py_library(
    name = "context",
    srcs = ["context.py"],
)

py_library(
    name = "memcache_decorator",
    srcs = ["memcache_decorator.py"],
    deps = [":context"],
)

py_library(
    name = "datastore_locks",
    srcs = ["datastore_locks.py"],
)

py_binary(
    name = "ng_template",
    srcs = ["ng_template.py"],
)

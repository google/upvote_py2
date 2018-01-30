"""Abstraction layer for build rules."""

load("@io_bazel_rules_appengine//appengine:py_appengine.bzl", "py_appengine_test", "py_appengine_binary")

py_appengine_library = native.py_library

def upvote_appengine_test(name, srcs, deps=[], data=[], size="medium"):  # pylint: disable=unused-argument
  py_appengine_test(
      name=name, srcs=srcs, deps=deps, data=data,
      libraries = {
          "webapp2": "latest",
          "jinja2": "latest",
          "yaml": "latest",
      },
  )

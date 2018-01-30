"""ng_template_bundle."""
load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_library")

def ng_template_bundle(name, srcs, module_name="templates",
                       strip_prefix=None, prepend_prefix=None, goog_provide=None):
  """Generates a js_library that inlines a set of Angular templates."""
  native.genrule(
      name = name + "_genrule",
      srcs = srcs,
      outs = [
          name + "_bundle.js",
      ],
      cmd = "$(location //common:ng_template) $(location @org_pubref_rules_node_toolchain//:bin/node) $(location @npm_html2js//:bin/ng-html2js) %s %s %s %s $(SRCS) > $@" % (strip_prefix, prepend_prefix, module_name, goog_provide),
      tools = [
          "@npm_html2js//:bin/ng-html2js",
          "@npm_html2js//:modules",
          "@org_pubref_rules_node_toolchain//:bin/node",
          "//common:ng_template",
      ],
  )

  closure_js_library(
      name = name,
      srcs = [name + "_genrule"],
      # Include the .ng files as data dependencies so binaries can serve them.
      data = srcs
  )


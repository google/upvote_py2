"""ng_template_bundle."""

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_library")

def ng_template_bundle(
        name,
        srcs,
        module_name = "templates",
        strip_prefix = None,
        prepend_prefix = None,
        goog_provide = None):
    """Generates a js_library that inlines a set of Angular templates."""
    native.genrule(
        name = name + "_genrule",
        srcs = srcs,
        outs = [
            name + "_bundle.js",
        ],
        cmd = "$(location //common:ng_template) $(location @npm_html2js//:ng-html2js_bin) %s %s %s %s $(SRCS) > $@" % (strip_prefix, prepend_prefix, module_name, goog_provide),
        tools = [
            "@npm_html2js//:ng-html2js_bin",
            "@npm_html2js//:_all_",
            "//common:ng_template",
        ],
    )

    closure_js_library(
        name = name,
        srcs = [name + "_genrule"],
        # Include the .ng files as data dependencies so binaries can serve them.
        data = srcs,
    )

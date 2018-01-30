package(default_visibility = ["//upvote"])

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_library", "closure_js_binary", "closure_js_test", "closure_css_library", "closure_css_binary")

closure_css_library(
    name = "css_lib",
    srcs = glob(["**/*.css"]),
)

closure_css_binary(
    name = "app_css",
    defs = ["--allow-unrecognized-properties"],
    renaming = False,
    deps = [
        ":css_lib",
        "@material_steppers//:material_steppers_css",
    ],
)

closure_js_library(
    name = "closure_lib",
    srcs = glob(
        ["**/*.js"],
        exclude = [
            "**/*_test.js",
        ],
    ),
    suppress = [
        "undefinedVars",
        "checkTypes",
        "functionParams",
        "reportUnknownTypes",
        "analyzerChecks",
        "JSC_INCORRECT_SHORTNAME_CAPITALIZATION",
    ],
    deps = [
        ":admin_templates",
        ":ui_templates",
        "@com_google_javascript_closure_library//:array",
        "@com_google_javascript_closure_library//:asserts",
        "@com_google_javascript_closure_library//:base",
        "@com_google_javascript_closure_library//:uri",
        "@material_steppers",
    ],
)

closure_js_binary(
    name = "app_min",
    compilation_level = "WHITESPACE_ONLY",
    data = glob(["web_ui/static/*"]),
    defs = [
        "--angular_pass",
        "--export_local_property_definitions",
    ],
    entry_points = [
        "goog:upvote.app.module",
        "goog:upvote.admin.app.module",
    ],
    language = "ECMASCRIPT_2015",
    deps = [
        ":closure_lib",
    ],
)

load("//common:build_defs.bzl", "ng_template_bundle")

ng_template_bundle(
    name = "admin_templates",
    srcs = glob(["admin_ui/**/*.html"]),
    goog_provide = "upvote.admin.templates.module",
    module_name = "upvote.admin.templates",
    prepend_prefix = "/admin/static/",
    strip_prefix = "upvote/gae/modules/upvote_app/frontend/admin_ui/",
)

ng_template_bundle(
    name = "ui_templates",
    srcs = glob(["web_ui/**/*.html"]),
    goog_provide = "upvote.templates.module",
    module_name = "upvote.templates",
    prepend_prefix = "/static/",
    strip_prefix = "upvote/gae/modules/upvote_app/frontend/web_ui/",
)

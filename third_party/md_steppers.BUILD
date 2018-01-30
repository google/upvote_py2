package(default_visibility = ["//visibility:public"])

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_css_library", "closure_js_library", "closure_js_binary", "closure_js_test")

genrule(
    name = "gen_material_steppers",
    srcs = ["dist/material-steppers.js"],
    outs = ["md-stepper.js"],
    cmd = "echo '\ngoog.provide(\"StepperCtrl\");\n' > $@; cat $(location dist/material-steppers.js) >> $@;",
)

closure_js_library(
    name = "material_steppers",
    srcs = ["md-stepper.js"],
)

closure_css_library(
    name = "material_steppers_css",
    srcs = ["dist/material-steppers.css"],
)

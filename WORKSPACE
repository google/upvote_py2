git_repository(
    name = "io_bazel_rules_appengine",
    commit = "d8136f0d4e71e8c70cbd3514eaeed9d41a67a85f",
    remote = "https://github.com/bazelbuild/rules_appengine.git",
)

load("@io_bazel_rules_appengine//appengine:py_appengine.bzl", "py_appengine_repositories")

py_appengine_repositories()

# needed for mock, webtest
new_http_archive(
    name = "six_archive",
    build_file = "//third_party:six.BUILD",
    sha256 = "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a",
    strip_prefix = "six-1.10.0",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz",
        "https://pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz",
    ],
)

bind(
    name = "six",
    actual = "@six_archive//:six",
)

new_http_archive(
    name = "mock_archive",
    build_file = "//third_party:mock.BUILD",
    sha256 = "b839dd2d9c117c701430c149956918a423a9863b48b09c90e30a6013e7d2f44f",
    strip_prefix = "mock-1.0.1",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/a2/52/7edcd94f0afb721a2d559a5b9aae8af4f8f2c79bc63fdbe8a8a6c9b23bbe/mock-1.0.1.tar.gz",
        "https://pypi.python.org/packages/a2/52/7edcd94f0afb721a2d559a5b9aae8af4f8f2c79bc63fdbe8a8a6c9b23bbe/mock-1.0.1.tar.gz",
    ],
)

bind(
    name = "mock",
    actual = "@mock_archive//:mock",
)

bind(
    name = "webob",
    actual = "@com_google_appengine_python//:webob-latest",
)

# needed for webtest
new_http_archive(
    name = "waitress_archive",
    build_file = "//third_party:waitress.BUILD",
    sha256 = "c74fa1b92cb183d5a3684210b1bf0a0845fe8eb378fa816f17199111bbf7865f",
    strip_prefix = "waitress-1.0.2",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/cd/f4/400d00863afa1e03618e31fd7e2092479a71b8c9718b00eb1eeb603746c6/waitress-1.0.2.tar.gz",
        "https://pypi.python.org/packages/cd/f4/400d00863afa1e03618e31fd7e2092479a71b8c9718b00eb1eeb603746c6/waitress-1.0.2.tar.gz",
    ],
)

bind(
    name = "waitress",
    actual = "@waitress_archive//:waitress",
)

# needed for webtest
new_http_archive(
    name = "beautifulsoup4_archive",
    build_file = "//third_party:beautifulsoup4.BUILD",
    sha256 = "b21ca09366fa596043578fd4188b052b46634d22059e68dd0077d9ee77e08a3e",
    strip_prefix = "beautifulsoup4-4.5.3",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/9b/a5/c6fa2d08e6c671103f9508816588e0fb9cec40444e8e72993f3d4c325936/beautifulsoup4-4.5.3.tar.gz",
        "https://pypi.python.org/packages/9b/a5/c6fa2d08e6c671103f9508816588e0fb9cec40444e8e72993f3d4c325936/beautifulsoup4-4.5.3.tar.gz",
    ],
)

bind(
    name = "beautifulsoup4",
    actual = "@beautifulsoup4_archive//:beautifulsoup4",
)

new_http_archive(
    name = "webtest_archive",
    build_file = "//third_party:webtest.BUILD",
    sha256 = "2b6abd2689f28a0b3575bcb5a36757f2344670dd13a8d9272d3a987c2fd1b615",
    strip_prefix = "WebTest-2.0.27",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/80/fa/ca3a759985c72e3a124cbca3e1f8a2e931a07ffd31fd45d8f7bf21cb95cf/WebTest-2.0.27.tar.gz",
        "https://pypi.python.org/packages/80/fa/ca3a759985c72e3a124cbca3e1f8a2e931a07ffd31fd45d8f7bf21cb95cf/WebTest-2.0.27.tar.gz",
    ],
)

bind(
    name = "webtest",
    actual = "@webtest_archive//:webtest",
)

git_repository(
    name = "absl_git",
    commit = "ed0faa035139d118806802c06eba7f02abd3e2a9",
    remote = "https://github.com/abseil/abseil-py.git",
)

new_git_repository(
    name = "rsa_git",
    build_file = "//third_party:rsa.BUILD",
    commit = "d00852509aa3702827941882941dc1c76368cf8c",
    remote = "https://github.com/sybrenstuvel/python-rsa.git",
)

bind(
    name = "rsa",
    actual = "@rsa_git//:rsa",
)

new_git_repository(
    name = "pyasn1_git",
    build_file = "//third_party:pyasn1.BUILD",
    commit = "24d5afade36b05d7ba79460b8a9d4e5d99e19918",
    remote = "https://github.com/etingof/pyasn1.git",
)

bind(
    name = "pyasn1",
    actual = "@pyasn1_git//:pyasn1",
)

new_git_repository(
    name = "oauth2client_git",
    build_file = "//third_party:oauth2client.BUILD",
    commit = "97320af2733f7bdbe47f067327610e348f953ae1",
    remote = "https://github.com/google/oauth2client.git",
)

bind(
    name = "oauth2client",
    actual = "@oauth2client_git//:oauth2client",
)

# needed for googleapiclient
new_http_archive(
    name = "uritemplate_archive",
    build_file = "//third_party:uritemplate.BUILD",
    sha256 = "c02643cebe23fc8adb5e6becffe201185bf06c40bda5c0b4028a93f1527d011d",
    strip_prefix = "uritemplate-3.0.0",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/cd/db/f7b98cdc3f81513fb25d3cbe2501d621882ee81150b745cdd1363278c10a/uritemplate-3.0.0.tar.gz",
        "https://pypi.python.org/packages/cd/db/f7b98cdc3f81513fb25d3cbe2501d621882ee81150b745cdd1363278c10a/uritemplate-3.0.0.tar.gz",
    ],
)

bind(
    name = "uritemplate",
    actual = "@uritemplate_archive//:uritemplate",
)

new_git_repository(
    name = "googleapiclient_git",
    build_file = "//third_party:googleapiclient.BUILD",
    remote = "https://github.com/google/google-api-python-client.git",
    tag = "v1.5.5",
)

bind(
    name = "googleapiclient",
    actual = "@googleapiclient_git//:googleapiclient",
)

# needed for requests
new_git_repository(
    name = "certifi_git",
    build_file = "//third_party:certifi.BUILD",
    remote = "https://github.com/certifi/python-certifi.git",
    tag = "2017.04.17",
)

bind(
    name = "certifi",
    actual = "@certifi_git//:certifi",
)

# needed for requests
new_git_repository(
    name = "idna_git",
    build_file = "//third_party:idna.BUILD",
    remote = "https://github.com/kjd/idna.git",
    tag = "v2.5",
)

bind(
    name = "idna",
    actual = "@idna_git//:idna",
)

# needed for requests
new_git_repository(
    name = "urllib3_git",
    build_file = "//third_party:urllib3.BUILD",
    remote = "https://github.com/shazow/urllib3.git",
    tag = "1.22",
)

bind(
    name = "urllib3",
    actual = "@urllib3_git//:urllib3",
)

# needed for requests
new_git_repository(
    name = "chardet_git",
    build_file = "//third_party:chardet.BUILD",
    remote = "https://github.com/chardet/chardet.git",
    tag = "3.0.2",
)

bind(
    name = "chardet",
    actual = "@chardet_git//:chardet",
)

# needed for gcloud_bigquery
new_git_repository(
    name = "requests_git",
    build_file = "//third_party:requests.BUILD",
    remote = "https://github.com/requests/requests.git",
    tag = "v2.17.3",
)

bind(
    name = "requests",
    actual = "@requests_git//:requests",
)

# needed for gcloud_core, oauth2client
new_http_archive(
    name = "httplib2_archive",
    build_file = "//third_party:httplib2.BUILD",
    sha256 = "c3aba1c9539711551f4d83e857b316b5134a1c4ddce98a875b7027be7dd6d988",
    strip_prefix = "httplib2-0.9.2/python2",
    urls = [
        "https://mirror.bazel.build/pypi.python.org/packages/ff/a9/5751cdf17a70ea89f6dde23ceb1705bfb638fd8cee00f845308bf8d26397/httplib2-0.9.2.tar.gz",
        "https://pypi.python.org/packages/ff/a9/5751cdf17a70ea89f6dde23ceb1705bfb638fd8cee00f845308bf8d26397/httplib2-0.9.2.tar.gz",
    ],
)

bind(
    name = "httplib2",
    actual = "@httplib2_archive//:httplib2",
)

# needed for gcloud_core
new_http_archive(
    name = "gapi_protos_http",
    build_file = "//third_party:gapi_protos.BUILD",
    sha256 = "f94cc66efba677a086b8b17b1240239433495b77631cd410f70151a8ff14435d",
    strip_prefix = "googleapis-common-protos-1.5.2",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/96/6a/34759a4a2119a8aae0b19d045917ee4a39ffaaeda2df3a892730fdcda408/googleapis-common-protos-1.5.2.tar.gz",
        "https://pypi.python.org/packages/96/6a/34759a4a2119a8aae0b19d045917ee4a39ffaaeda2df3a892730fdcda408/googleapis-common-protos-1.5.2.tar.gz",
    ],
)

bind(
    name = "gapi_protos",
    actual = "@gapi_protos_http//:gapi_protos",
)

# needed for gcloud_core
new_http_archive(
    name = "protobuf_archive",
    build_file = "//third_party:protobuf.BUILD",
    sha256 = "1cbcee2c45773f57cb6de7ee0eceb97f92b9b69c0178305509b162c0160c1f04",
    strip_prefix = "protobuf-3.3.0",
    urls = [
        "http://mirror.bazel.build/pypi.python.org/packages/56/28/6263d846f60dad93939fd3a22d712d6bae3bf3484332d22bd5933dec8c99/protobuf-3.3.0.tar.gz",
        "https://pypi.python.org/packages/56/28/6263d846f60dad93939fd3a22d712d6bae3bf3484332d22bd5933dec8c99/protobuf-3.3.0.tar.gz",
    ],
)

bind(
    name = "protobuf",
    actual = "@protobuf_archive//:protobuf",
)

# needed for gcloud_core
new_git_repository(
    name = "gcloud_auth_httplib2_git",
    build_file = "//third_party:gcloud_auth_httplib2.BUILD",
    commit = "136da2cd50aa7deb769062cf1d77259d64743a7f",
    remote = "https://github.com/GoogleCloudPlatform/google-auth-library-python-httplib2.git",
)

bind(
    name = "gcloud_auth_httplib2",
    actual = "@gcloud_auth_httplib2_git//:gcloud_auth_httplib2",
)

# needed for gcloud_bigquery
new_http_archive(
    name = "gcloud_core_archive",
    build_file = "//third_party:gcloud_core.BUILD",
    sha256 = "1249ee44c445f820eaf99d37904b37961347019dcd3637dbad1f3173260245f2",
    strip_prefix = "google-cloud-core-0.25.0",
    urls = [
        "https://mirror.bazel.build/pypi.python.org/packages/58/d0/c3a30eca2a0073d5ac00254a1a9d259929a899deee6e3dfe4e45264f5187/google-cloud-core-0.25.0.tar.gz",
        "https://pypi.python.org/packages/58/d0/c3a30eca2a0073d5ac00254a1a9d259929a899deee6e3dfe4e45264f5187/google-cloud-core-0.25.0.tar.gz",
    ],
)

bind(
    name = "gcloud_core",
    actual = "@gcloud_core_archive//:gcloud_core",
)

# needed for gcloud_bigquery
new_git_repository(
    name = "gcloud_resumable_media_git",
    build_file = "//third_party:gcloud_resumable_media.BUILD",
    remote = "https://github.com/GoogleCloudPlatform/google-resumable-media-python.git",
    tag = "0.2.1",
)

bind(
    name = "gcloud_resumable_media",
    actual = "@gcloud_resumable_media_git//:gcloud_resumable_media",
)

# needed for gcloud_auth
new_git_repository(
    name = "pyasn1_modules_git",
    build_file = "//third_party:pyasn1_modules.BUILD",
    remote = "https://github.com/etingof/pyasn1-modules.git",
    tag = "v0.0.10",
)

bind(
    name = "pyasn1_modules",
    actual = "@pyasn1_modules_git//:pyasn1_modules",
)

# needed for gcloud_auth
new_git_repository(
    name = "cachetools_git",
    build_file = "//third_party:cachetools.BUILD",
    remote = "https://github.com/tkem/cachetools.git",
    tag = "v2.0.0",
)

bind(
    name = "cachetools",
    actual = "@cachetools_git//:cachetools",
)

# needed for gcloud_bigquery
new_git_repository(
    name = "gcloud_auth_git",
    build_file = "//third_party:gcloud_auth.BUILD",
    remote = "https://github.com/GoogleCloudPlatform/google-auth-library-python.git",
    tag = "v1.0.0",
)

bind(
    name = "gcloud_auth",
    actual = "@gcloud_auth_git//:gcloud_auth",
)

new_http_archive(
    name = "gcloud_bigquery_archive",
    build_file = "//third_party:gcloud_bigquery.BUILD",
    sha256 = "6e8cc6914701bbfd8845cc0e0b19c5e2123649fc6ddc49aa945d83629499f4ec",
    strip_prefix = "google-cloud-bigquery-0.25.0",
    urls = [
        "https://mirror.bazel.build/pypi.python.org/packages/4a/f1/05631b0a29b1f763794404195d161edb24d7463029c987e0a32fc521e2a6/google-cloud-bigquery-0.25.0.tar.gz",
        "https://pypi.python.org/packages/4a/f1/05631b0a29b1f763794404195d161edb24d7463029c987e0a32fc521e2a6/google-cloud-bigquery-0.25.0.tar.gz",
    ],
)

bind(
    name = "gcloud_bigquery",
    actual = "@gcloud_bigquery_archive//:gcloud_bigquery",
)

new_http_archive(
    name = "requests_toolbelt_archive",
    build_file = "//third_party:requests_toolbelt.BUILD",
    sha256 = "f6a531936c6fa4c6cfce1b9c10d5c4f498d16528d2a54a22ca00011205a187b5",
    strip_prefix = "requests-toolbelt-0.8.0",
    urls = [
        "https://pypi.python.org/packages/86/f9/e80fa23edca6c554f1994040064760c12b51daff54b55f9e379e899cd3d4/requests-toolbelt-0.8.0.tar.gz",
    ],
)

bind(
    name = "requests_toolbelt",
    actual = "@requests_toolbelt_archive//:requests_toolbelt",
)

new_http_archive(
    name = "com_google_javascript_closure_library",
    build_file = "//third_party:closure_library.BUILD",
    sha256 = "d018003a6895141f6e24b11fd969f6a9ad7756fc15dff6acfb49e2aab1d02b14",
    strip_prefix = "closure-library-20170626",
    urls = [
        "http://mirror.bazel.build/github.com/google/closure-library/archive/v20170626.tar.gz",
        "https://github.com/google/closure-library/archive/v20170626.tar.gz",
    ],
)

http_archive(
    name = "io_bazel_rules_closure",
    sha256 = "110fe68753413777944b473c25eed6368c4a0487cee23a7bac1b13cc49d3e257",
    strip_prefix = "rules_closure-4af89ef1db659eb41f110df189b67d4cf14073e1",
    urls = [
        "http://github.com/bazelbuild/rules_closure/archive/4af89ef1db659eb41f110df189b67d4cf14073e1.tar.gz",
    ],
)

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_repositories")

closure_repositories(omit_com_google_javascript_closure_library = True)

git_repository(
    name = "org_pubref_rules_node",
    commit = "f6fff71fe8b1bee8d3a22e50eca0f76427ab939e",
    remote = "https://github.com/pubref/rules_node.git",
)

load("@org_pubref_rules_node//node:rules.bzl", "node_repositories", "npm_repository")

node_repositories()

npm_repository(
    name = "npm_html2js",
    deps = {
        "ng-html2js": "3.0.0",
    },
)

new_git_repository(
    name = "material_steppers",
    build_file = "//third_party:md_steppers.BUILD",
    commit = "042f812382aa16eada6078594582150fa5dc7235",
    remote = "https://github.com/eberlitz/material-steppers.git",
)

// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

goog.provide('upvote.packagecontents.PackageContents');

goog.require('upvote.app.constants');
goog.require('upvote.packagecontents.PackageContentsController');

/** @type {!angular.Component} */
upvote.packagecontents.PackageContents = {
  'bindings': {
    'contents': '<',
    'mainCertId': '<',
    'packageId': '<',
    'packageName': '<'
  },
  'controller': upvote.packagecontents.PackageContentsController,
  'controllerAs': 'ctrl',
  'templateUrl': upvote.app.constants.STATIC_URL_PREFIX +
      'components/packagecontents/contents.html',
};

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

goog.provide('upvote.statechip.StatechipHelpController');

goog.require('upvote.app.constants');
goog.require('upvote.dialog.DialogLauncherController');

upvote.statechip.StatechipHelpController =
    class extends upvote.dialog.DialogLauncherController {
  /**
   * @param {!md.$panel} $mdPanel
   * @param {!angular.JQLite} $element
   * @ngInject
   */
  constructor($mdPanel, $element) {
    super(
        upvote.app.constants.STATIC_URL_PREFIX +
            'components/statechip/help/dialog.html',
        '.animation-target', $mdPanel, $element);
  }
};

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

goog.provide('upvote.packagecontents.PackageContentsController');

goog.require('goog.asserts');
goog.require('upvote.app.constants');
goog.require('upvote.dialog.DialogController');
goog.require('upvote.dialog.DialogLauncherController');

upvote.packagecontents.PackageContentsController =
    class extends upvote.dialog.DialogLauncherController {
  /**
   * @param {!md.$panel} $mdPanel
   * @param {!angular.JQLite} $element
   * @param {!angular.Scope} $scope
   * @ngInject
   */
  constructor($mdPanel, $element, $scope) {
    super(
        upvote.app.constants.STATIC_URL_PREFIX +
            'components/packagecontents/dialog.html',
        '#package-contents-button', $mdPanel, $element);

    /** @export {!Array<!upvote.shared.models.SantaBundleBinary>} */
    this.contents;
    /** @export {string} */
    this.mainCertId;
    /** @export {string} */
    this.packageId;
    /** @export {string} */
    this.packageName;
  }

  /** @export */
  $onInit() {
    goog.asserts.assert(this.contents, 'set by ng bindToController');
    goog.asserts.assertString(this.mainCertId, 'set by ng bindToController');
    goog.asserts.assertString(this.packageId, 'set by ng bindToController');
    goog.asserts.assertString(this.packageName, 'set by ng bindToController');
  }

  /** @export */
  $onChanges() {
    this.overrides = {
      'locals': {
        'contents': this.contents,
        'mainCertId': this.mainCertId,
        'packageId': this.packageId,
        'packageName': this.packageName,
      },
      // NOTE: Because md-list is dynamically sized, the relative
      // positioning based on size results in the panel clipping off the screen.
      'position':
          this.mdPanel.newPanelPosition().absolute().centerVertically().right(),
      'controller': upvote.packagecontents.PackageContentsDialogController,
    };
  }
};


/** Controller for the package contents dialog. */
upvote.packagecontents.PackageContentsDialogController =
    class extends upvote.dialog.DialogController {
  /**
   * @param {!md.$panel.MdPanelRef} mdPanelRef
   * @param {!Array<!upvote.shared.models.SantaBundleBinary>} contents
   * @param {string} mainCertId
   * @param {string} packageId
   * @param {string} packageName
   * @ngInject
   */
  constructor(mdPanelRef, contents, mainCertId, packageId, packageName) {
    super(mdPanelRef);

    /** @export {!Array<!upvote.shared.models.SantaBundleBinary>} */
    this.contents = contents;
    /** @export {string} */
    this.mainCertId = mainCertId;
    /** @export {string} */
    this.packageId = packageId;
    /** @export {string} */
    this.packageName = packageName;
  }
};

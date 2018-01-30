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

goog.provide('upvote.dialog.DialogLauncherController');

goog.require('upvote.dialog.DialogController');


upvote.dialog.DialogLauncherController = class {
  /**
   * @param {!string} dialogTemplateUrl The URL of the template to be rendered
   *     in the generated dialog.
   * @param {!string} animationTarget The element selector used as the origin
   *     point for launching the dialog.
   * @param {!md.$panel} $mdPanel
   * @param {!angular.JQLite} $element
   */
  constructor(dialogTemplateUrl, animationTarget, $mdPanel, $element) {
    /** @private {!string} */
    this.templateUrl_ = dialogTemplateUrl;
    /** @private {!string} */
    this.target_ = animationTarget;
    /** @protected {!md.$panel} */
    this.mdPanel = $mdPanel;
    /** @private {!angular.JQLite} */
    this.element_ = $element;

    /** @protected {?Object} */
    this.overrides;
  }

  /**
   * Show the help dialog.
   * @export
   */
  showDialog() {
    // Describes the order of alignment preferences.
    let position =
        this.mdPanel.newPanelPosition()
            .relativeTo(this.element_)
            .addPanelPosition(
                this.mdPanel.xPosition.ALIGN_START,
                this.mdPanel.yPosition.ALIGN_BOTTOMS)
            .addPanelPosition(
                this.mdPanel.xPosition.ALIGN_START,
                this.mdPanel.yPosition.CENTER)
            .addPanelPosition(
                this.mdPanel.xPosition.ALIGN_START,
                this.mdPanel.yPosition.ALIGN_TOPS)
            .addPanelPosition(
                this.mdPanel.xPosition.CENTER,
                this.mdPanel.yPosition.ALIGN_BOTTOMS)
            .addPanelPosition(
                this.mdPanel.xPosition.CENTER,
                this.mdPanel.yPosition.ALIGN_TOPS)
            .addPanelPosition(
                this.mdPanel.xPosition.CENTER, this.mdPanel.yPosition.CENTER);

    let animation = this.mdPanel.newPanelAnimation()
                        .openFrom(this.target_)
                        .closeTo(this.target_)
                        .withAnimation(this.mdPanel.animation.SCALE);
    let baseConfig = {
      'animation': animation,
      'attachTo':
          angular.element(document.body.querySelector('#uv-all-content')),
      'controller': upvote.dialog.DialogController,
      'controllerAs': 'ctrl',
      'templateUrl': this.templateUrl_,
      'position': position,
      'zIndex': 150,
      'escapeToClose': true,
      'clickOutsideToClose': true,
      'hasBackdrop': false,
    };
    let config = Object.assign(baseConfig, this.overrides);

    this.mdPanel.open(config);
  }
};

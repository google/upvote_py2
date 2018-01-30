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

goog.provide('upvote.admin.emergencypage.EmergencyController');

goog.require('upvote.shared.Page');


/** Controller for the Big Red Button. */
upvote.admin.emergencypage.EmergencyController = class {
  /**
   * @param {!angular.Resource} emergencyResource
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(emergencyResource, errorService, page) {
    /** @private {!angular.Resource} */
    this.emergencyResource_ = emergencyResource;
    /** @private {!upvote.errornotifier.ErrorService} */
    this.errorService_ = errorService;

    /** @export {?Object} */
    this.buttonStatus = null;

    page.title = 'Emergency';

    this.init_();
  }

  /** @private */
  init_() {
    this.emergencyResource_.get()['$promise']
        .then((response) => {
          this.buttonStatus = response;
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
  }

  /**
   * Set the state of a button.
   * @param {string} button The name of the button to be set.
   * @param {boolean} value The boolean value to which the button state should
   *     be set.
   * @private
   */
  setButton_(button, value) {
    let routeName = 'setBigRedButton' + button;
    let buttonName = 'bigRedButton' + button;
    this.emergencyResource_[routeName](
            {'value': this.buttonStatus[buttonName]})['$promise']
        .then((response) => {
          this.buttonStatus = response;
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
  }

  /**
   * @param {boolean} value
   * @export
   */
  setBigRedButton(value) {
    this.setButton_('', value);
  }

  /**
   * @param {boolean} value
   * @export
   */
  setBigRedButtonStop1(value) {
    this.setButton_('Stop1', value);
  }

  /**
   * @param {boolean} value
   * @export
   */
  setBigRedButtonStop2(value) {
    this.setButton_('Stop2', value);
  }

  /**
   * @param {boolean} value
   * @export
   */
  bigRedButtonGo1(value) {
    this.setButton_('Go1', value);
  }

  /**
   * @param {boolean} value
   * @export
   */
  bigRedButtonGo2(value) {
    this.setButton_('Go2', value);
  }
};

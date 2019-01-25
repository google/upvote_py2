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

goog.provide('upvote.exemptionrequestpage.ExemptionRequestController');

goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.exemptions.ExemptionDuration');
goog.require('upvote.exemptions.ExemptionReason');
goog.require('upvote.exemptions.ExemptionRequestData');
goog.require('upvote.exemptions.ExemptionService');
goog.require('upvote.hosts.HostService');
goog.require('upvote.shared.Page');
goog.require('upvote.shared.models.AnyHost');

goog.scope(() => {
const ExemptionDuration = upvote.exemptions.ExemptionDuration;
const ExemptionReason = upvote.exemptions.ExemptionReason;


/** Controller for host request page. */
upvote.exemptionrequestpage.ExemptionRequestController = class {
  /**
   * @param {!upvote.exemptions.ExemptionService} exemptionService
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$routeParams} $routeParams
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(exemptionService, hostService, errorService, $routeParams, page) {
    /** @const @private {!upvote.exemptions.ExemptionService} */
    this.exemptionService_ = exemptionService;
    /** @private {!upvote.hosts.HostService} */
    this.hostService_ = hostService;
    /** @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @private {!angular.$routeParams} $routeParams */
    this.routeParams_ = $routeParams;

    /** @export {?string} */
    this.id = null;
    /** @export {?upvote.shared.models.AnyHost} */
    this.host = null;
    /** @export {boolean} */
    this.requested = false;

    /** @export {!Object<string, string>} */
    this.reasonDescriptions = ExemRequestCtrl.REASON_DESCRIPTIONS;

    /** @export {!upvote.exemptions.ExemptionRequestData} */
    this.requestData = {
      'reason': ExemptionReason['DEVELOPER_MACOS'],
      'otherText': null,
      'duration': ExemptionDuration['YEAR'],
    };

    page.title = 'Exemption Request';

    this.init_();
  }

  /** @private */
  init_() {
    this.id = this.routeParams_['id'];

    this.hostService_.get(this.id)
        .then((response) => {
          this.host = response['data'];
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }

  /**
   * Returns whether "Other" is selected as the reason.
   * @returns {boolean}
   * @export
   */
  isOtherSelected() {
    return this.requestData['reason'] == ExemptionReason['OTHER'];
  }

  /**
   * Submit the exception request.
   * @export
   */
  submitRequest() {
    if (!this.id) {
      this.errorService_.createSimpleToast(
          'Failed to submit request: ID is null');
    } else if (this.isOtherSelected() && !this.requestData['otherText']) {
      this.errorService_.createSimpleToast(
          'Please explain why you\'ve selected "Other"');
    } else {
      this.exemptionService_.requestExemption(this.id, this.requestData)
          .then((response) => {
            this.requested = true;
          })
          .catch((response) => {
            // If there's an existing request, detect the HTTP CONFLICT code and
            // alert the user
            if (response['status'] == 409) {
              this.errorService_.createSimpleToast(
                  'You\'ve already submitted a request for this Host');
            } else {
              this.errorService_.createDialogFromError(response);
            }
          });
    }
  }
};
let ExemRequestCtrl = upvote.exemptionrequestpage.ExemptionRequestController;

/** @export {!Object<string, string>} */
ExemRequestCtrl.REASON_DESCRIPTIONS = {};
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['DEVELOPER_MACOS']] =
    'As part of my job role, I develop macOS software on this machine.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['DEVELOPER_IOS']] =
    'As part of my job role, I develop iOS software on this machine.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['DEVELOPER_DEVTOOLS']] =
    'As part of my job role, I develop and/or test developer tools ' +
    '(e.g. compilers) on this machine.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['DEVELOPER_PERSONAL']] =
    'I develop on this machine for personal projects/use.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['USES_PACKAGE_MANAGER']] =
    'I use a package manager (e.g. Homebrew) on this machine.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['FEARS_NEGATIVE_IMPACT']] =
    'I\'m afraid Santa will have a negative impact on my work but I\'m ' +
    'not sure why.';
ExemRequestCtrl.REASON_DESCRIPTIONS[ExemptionReason['OTHER']] =
    'Other, please explain';
});  // goog.scope

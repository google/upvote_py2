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

goog.provide('upvote.virustotal.VirusTotalWidgetController');

goog.require('goog.asserts');
goog.require('upvote.shared.models.AnyBlockable');
goog.require('upvote.signalindicator.ANALYSIS_STATE');
goog.require('upvote.virustotal.Report');
goog.require('upvote.virustotal.ResponseCode');


/** Controller for Virus Total widget. */
upvote.virustotal.VirusTotalWidgetController = class {
  /**
   * @param {!angular.Resource} virusTotalResource
   * @param {!md.$dialog} $mdDialog
   * @param {!angular.$window} $window
   * @ngInject
   */
  constructor(virusTotalResource, $mdDialog, $window) {
    /** @export {!upvote.shared.models.AnyBlockable} */
    this.blockable;
    /** @export {!Array<!upvote.shared.models.SantaBundleBinary>} */
    this.contents;

    /** @private {!angular.Resource} */
    this.virusTotalResource_ = virusTotalResource;
    /** @private {!md.$dialog} */
    this.mdDialog_ = $mdDialog;
    /** @private {!angular.$window} */
    this.window_ = $window;

    /** @export {!boolean} */
    this.requestFailed = false;
    /** @export {?upvote.virustotal.Report} */
    this.report = null;

    /** @export {!boolean} */
    this.requestUpload = false;
  }

  /** @export */
  $onInit() {
    goog.asserts.assert(this.blockable, 'set by ng bindToController');
    goog.asserts.assert(this.contents, 'set by ng bindToController');

    // Check the state of the blockable in VirusTotal.
    this.virusTotalResource_['check'](
            {'hash': this.blockable['id']})['$promise']
        .then((successResponse) => {
          this.report = successResponse;
        })
        .catch((failureResponse) => {
          this.requestFailed = true;
        });
  }

  /**
   * Returns the analysis state of the VirusTotal report.
   * @return {!upvote.signalindicator.ANALYSIS_STATE}
   * @export
   */
  getState() {
    const states = upvote.signalindicator.ANALYSIS_STATE;
    const response = upvote.virustotal.ResponseCode;
    if (!this.report) {
      return states.UNKNOWN;
    } else if (this.report.positives > 0) {
      return states.BAD;
    } else if (this.report.responseCode == response.KNOWN) {
      return states.GOOD;
    } else if (this.report.responseCode == response.UNKNOWN) {
      return states.NONE;
    } else if (this.report.responseCode == response.QUEUED) {
      return states.PENDING;
    } else {
      return states.UNKNOWN;
    }
  }

  /**
   * Display the confirmation dialog for the upload action.
   * @param {Event} event_
   */
  showUploadConfirmation(event_) {
    let dialog =
        this.mdDialog_.confirm()
            .title('VirusTotal Upload Warning')
            .htmlContent(
                'Please ONLY upload binaries that are&hellip;' +
                '<ul>' +
                '<li>non-confidential</li>' +
                '<li>not subject to licensing constraints</li>' +
                '</ul>')
            .targetEvent(event_)
            .ok('Continue')
            .cancel('Cancel');
    this.mdDialog_.show(dialog).then(() => {
      this.window_.open('//www.virustotal.com');
    });
  }

  /**
   * Return whether the current blockable is a Package.
   * @return {boolean}
   * @export
   */
  isPackage() {
    return !!this.blockable && this.blockable['class_'].includes('Package');
  }
};

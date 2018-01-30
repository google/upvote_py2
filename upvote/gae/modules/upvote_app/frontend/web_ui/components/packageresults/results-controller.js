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

goog.provide('upvote.packageresults.PackageResultsController');

goog.require('goog.asserts');
goog.require('upvote.app.constants');
goog.require('upvote.dialog.DialogController');
goog.require('upvote.dialog.DialogLauncherController');
goog.require('upvote.signalindicator.ANALYSIS_STATE');
goog.require('upvote.virustotal.BundleReport');
goog.require('upvote.virustotal.Report');
goog.require('upvote.virustotal.ResponseCode');


/** Controller for package VirusTotal results button+dialog. */
upvote.packageresults.PackageResultsController =
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
            'components/packageresults/dialog.html',
        '#package-results-button', $mdPanel, $element);

    /** @export {!upvote.virustotal.BundleReport} */
    this.results;
    /** @export {!Array<!upvote.shared.models.SantaBundleBinary>} */
    this.contents;
  }

  /** @export */
  $onChanges() {
    this.overrides = {
      'locals': {'reportMap': this.getReportMap_()},
      // NOTE: Because md-list is dynamically sized, the relative
      // positioning based on size results in the panel clipping off the screen.
      'position':
          this.mdPanel.newPanelPosition().absolute().centerVertically().right(),
      'controller': upvote.packageresults.PackageResultsDialogController,
    };
  }

  /**
   * Returns a list of (report, binary) tuples for all package binaries.
   *
   * Maintains the order of the binaries as returned by the package contents API
   * route. This ensures consistency with the packagecontents component.
   * @return {?Array<!{
   *    report: !upvote.virustotal.Report,
   *    binary: !upvote.shared.models.SantaBundleBinary
   * }>}
   * @private
   */
  getReportMap_() {
    if (!this.contents || !this.results) {
      return null;
    }
    return this.contents.map((binary) => ({
                               'report': this.results['reports'][binary['id']],
                               'binary': binary
                             }));
  };
};


/** Controller for the VirusTotal results dialog. */
upvote.packageresults.PackageResultsDialogController =
    class extends upvote.dialog.DialogController {
  /**
   * @param {!md.$panel.MdPanelRef} mdPanelRef
   * @param {?Array<!{
   *    report: !upvote.virustotal.Report,
   *    binary: !upvote.shared.models.SantaBundleBinary
   * }>} reportMap
   * @ngInject
   */
  constructor(mdPanelRef, reportMap) {
    super(mdPanelRef);

    /**
     * @export {?Array<!{
     *    report: !upvote.virustotal.Report,
     *    binary: !upvote.shared.models.SantaBundleBinary
     * }>}
     */
    this.reportMap = reportMap;
  }

  /**
   * Returns the analysis state of the VirusTotal report.
   * @param {!upvote.virustotal.Report} report
   * @return {!upvote.signalindicator.ANALYSIS_STATE}
   * @export
   */
  getState(report) {
    const states = upvote.signalindicator.ANALYSIS_STATE;
    const response = upvote.virustotal.ResponseCode;
    if (!report) {
      return states.UNKNOWN;
    } else if (report.responseCode == response.KNOWN) {
      if (report.positives == 0) {
        return states.GOOD;
      } else {
        return states.BAD;
      }
    } else if (report.responseCode == response.UNKNOWN) {
      return states.NONE;
    } else if (report.responseCode == response.QUEUED) {
      return states.PENDING;
    } else {
      return states.UNKNOWN;
    }
  }
};

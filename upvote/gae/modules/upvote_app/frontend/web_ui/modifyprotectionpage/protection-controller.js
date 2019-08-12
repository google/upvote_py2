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

goog.provide('upvote.modifyprotectionpage.ModifyProtectionController');

goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.exemptions.ExemptionDuration');
goog.require('upvote.exemptions.ExemptionReason');
goog.require('upvote.exemptions.ExemptionService');
goog.require('upvote.features.FeatureService');
goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.ProtectionLevel');
goog.require('upvote.shared.Page');
goog.require('upvote.shared.constants.ExemptionState');
goog.require('upvote.shared.models.AnyHost');

goog.scope(() => {
const ExemptionDuration = upvote.exemptions.ExemptionDuration;
const ExemptionReason = upvote.exemptions.ExemptionReason;
const ProtectionLevel = upvote.hosts.ProtectionLevel;
const ExemptionState = upvote.shared.constants.ExemptionState;


/** Controller for the 'modify protection' page. */
upvote.modifyprotectionpage.ModifyProtectionController = class {
  /**
   * @param {!upvote.exemptions.ExemptionService} exemptionService
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!upvote.features.FeatureService} featureService
   * @param {!angular.$routeParams} $routeParams
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @param {!angular.Scope} $scope
   * @ngInject
   */
  constructor(
      exemptionService, hostService, errorService, featureService, $routeParams,
      page, $scope) {
    /** @const @private {!upvote.exemptions.ExemptionService} */
    this.exemptionService_ = exemptionService;
    /** @const @private {!upvote.hosts.HostService} */
    this.hostService_ = hostService;
    /** @const @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @const @private {!upvote.features.FeatureService} featureService */
    this.featureService_ = featureService;
    /** @const @private {!angular.$routeParams} $routeParams */
    this.routeParams_ = $routeParams;
    /** @const @private {!upvote.shared.Page} */
    this.page_ = page;
    /** @const @private {!angular.Scope} */
    this.scope_ = $scope;
    /** @export {?string} */
    this.id = null;
    /** @export {?upvote.shared.models.AnyHost} */
    this.host = null;
    /** @export {boolean} */
    this.fullProtectionRequested = false;
    /** @export {boolean} */
    this.developerModeRequested = false;
    /** @export {boolean} */
    this.minimalProtectionRequested = false;

    /** @const @export {!Object<string, string>} */
    this.durations = {};
    this.durations[ExemptionDuration['DAY']] = 'One Day';
    this.durations[ExemptionDuration['WEEK']] = 'One Week';
    this.durations[ExemptionDuration['MONTH']] = 'One Month';
    this.durations[ExemptionDuration['YEAR']] = 'One Year';

    /** @const @export {!Object<string, string>} */
    this.reasons = {};
    this.reasons[ExemptionReason['DEVELOPER_MACOS']] = 'macOS Developer';
    this.reasons[ExemptionReason['DEVELOPER_IOS']] = 'iOS Developer';
    this.reasons[ExemptionReason['DEVELOPER_DEVTOOLS']] = 'Tool Developer';
    this.reasons[ExemptionReason['DEVELOPER_PERSONAL']] = 'Personal Developer';
    this.reasons[ExemptionReason['USES_PACKAGE_MANAGER']] =
        'Package Manager User';
    this.reasons[ExemptionReason['FEARS_NEGATIVE_IMPACT']] =
        'Fear Negative Impact';
    this.reasons[ExemptionReason['OTHER']] = 'Other';

    /** @export {!upvote.exemptions.ExemptionDuration} */
    this.duration = ExemptionDuration['MONTH'];

    /** @export {!upvote.exemptions.ExemptionReason} */
    this.reason = ExemptionReason['DEVELOPER_MACOS'];

    /** @export {?string} */
    this.otherText = null;

    this.page_.title = 'Modify Protection';

    this.init_();
  }

  /** @private */
  init_() {
    this.id = this.routeParams_['id'];

    this.hostService_.get(this.id)
        .then((response) => {
          this.host = response['data'];
          this.page_.title = 'Modify Protection: ' + this.host.hostname;
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }

  /**
   * Indicates if Developer Mode is available for the given host.
   * @return {boolean}
   * @export
   */
  isDeveloperModeAvailable() {
    let available =
        (this.host !== null && this.hostService_.isSantaHost(this.host));
    return available;
  }

  /**
   * Indicates if a given ProtectionLevel is enabled.
   * @param {!upvote.hosts.ProtectionLevel} level
   * @return {boolean}
   * @private
   */
  isProtectionLevelEnabled_(level) {
    if (this.host == null) {
      return true;  // Fail closed, disabling the buttons.
    }
    return this.hostService_.getProtectionLevel(this.host) == level;
  }

  /**
   * Indicates if ProtectionLevel FULL is enabled.
   * @return {boolean}
   * @export
   */
  isFullProtectionEnabled() {
    return this.isProtectionLevelEnabled_(ProtectionLevel.FULL);
  }

  /**
   * Indicates if ProtectionLevel FULL is enabled.
   * @return {boolean}
   * @export
   */
  isDeveloperModeEnabled() {
    return this.isProtectionLevelEnabled_(ProtectionLevel.DEVMODE);
  }

  /**
   * Indicates if ProtectionLevel FULL is enabled.
   * @return {boolean}
   * @export
   */
  isMinimalProtectionEnabled() {
    return this.isProtectionLevelEnabled_(ProtectionLevel.MINIMAL);
  }

  /**
   * Return whether there is an active request.
   * @return {boolean}
   * @private
   */
  hasActiveRequest_() {
    return (
        this.fullProtectionRequested || this.developerModeRequested ||
        this.minimalProtectionRequested);
  }

  /**
   * Return whether a host has an APPROVED Exemption.
   * @return {boolean}
   * @private
   */
  hasPendingExemption_() {
    if (this.host && this.host.exemption) {
      return this.host.exemption.state == ExemptionState.PENDING;
    }
    return false;
  }

  /**
   * Return whether the Full Protection button should be disabled.
   * @return {boolean}
   * @export
   */
  isFullProtectionButtonDisabled() {
    return (
        this.isFullProtectionEnabled() || this.hasActiveRequest_() ||
        this.hasPendingExemption_());
  }

  /**
   * Return whether the Developer Mode button should be disabled.
   * @return {boolean}
   * @export
   */
  isDeveloperModeButtonDisabled() {
    return (
        this.isDeveloperModeEnabled() || this.hasActiveRequest_() ||
        this.hasPendingExemption_());
  }

  /**
   * Return whether the Minimal Protection inputs should be disabled.
   * @return {boolean}
   * @export
   */
  isMinimalProtectionInputDisabled() {
    return (this.hasActiveRequest_() || this.hasPendingExemption_());
  }

  /**
   * Return whether the Minimal Protection button should be disabled.
   * @return {boolean}
   * @export
   */
  isMinimalProtectionButtonDisabled() {
    return (
        this.hasActiveRequest_() || this.hasPendingExemption_() ||
        this.scope_.minimalProtectionForm.$invalid);
  }

  /**
   * @param {boolean} enable
   * @private
   */
  setDeveloperMode_(enable) {
    this.hostService_.setTransitive(this.host.id, enable)
        .then((response) => {
          this.host = response['data'];
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        })
        .finally(() => {
          this.developerModeRequested = false;
          this.fullProtectionRequested = false;
        });
  }

  /**
   * Enables 'Developer Mode'.
   * @export
   */
  enableDeveloperMode() {
    this.developerModeRequested = true;
    this.setDeveloperMode_(true);
  }

  /**
   * Disables 'Developer Mode'.
   * @private
   */
  disableDeveloperMode_() {
    this.setDeveloperMode_(false);
  }

  /**
   * Enables 'Minimal Protection'.
   * @export
   */
  enableMinimalProtection() {
    this.minimalProtectionRequested = true;

    const requestData = {
      'duration': this.duration,
      'reason': this.reason,
      'otherText': this.otherText,
    };

    this.exemptionService_.requestExemption(this.host.id, requestData)
        .then((response) => {
          this.host['exemption'] = response['data']['exemption'];
          this.host['transitiveWhitelistingEnabled'] =
              response['data']['transitiveWhitelistingEnabled'];
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        })
        .finally(() => {
          this.minimalProtectionRequested = false;
        });
  }

  /**
   * Disables 'Minimal Protection'.
   * @private
   */
  disableMinimalProtection_() {
    this.exemptionService_.cancelExemption(this.host.id)
        .then((response) => {
          this.host['exemption'] = response['data']['exemption'];
          this.host['transitiveWhitelistingEnabled'] =
              response['data']['transitiveWhitelistingEnabled'];
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        })
        .finally(() => {
          this.fullProtectionRequested = false;
        });
  }

  /**
   * Enables 'Full Protection'.
   * @export
   */
  enableFullProtection() {
    this.fullProtectionRequested = true;
    if (this.isDeveloperModeEnabled()) {
      this.disableDeveloperMode_();
    } else if (this.isMinimalProtectionEnabled()) {
      this.disableMinimalProtection_();
    }
  }
};
let ModProCtrl = upvote.modifyprotectionpage.ModifyProtectionController;
});  // goog.scope

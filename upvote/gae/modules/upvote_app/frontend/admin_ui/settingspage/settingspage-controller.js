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

goog.provide('upvote.admin.settingspage.Settings');
goog.provide('upvote.admin.settingspage.SettingsController');

goog.require('upvote.admin.settings.SettingsService');
goog.require('upvote.shared.Page');


/** @typedef {{virustotal: string, bit9:string}} */
upvote.admin.settingspage.ApiKeyStruct;

/**
 * Class containing all settings.
 * @unrestricted
 */
upvote.admin.settingspage.Settings = class {
  constructor() {
    /** @export {boolean} */
    this.debug = false;
    /** @export {number} */
    this.santaEventBatchSize = 0;
    /** @export {number} */
    this.santaRuleBatchSize = 0;
    /** @export {boolean} */
    this.santaBundlesEnabled = true;
    /** @export {number} */
    this.santaRequireXsrf = 0;
    /** @export {number} */
    this.votingThresholds = 0;
    /** @export {!Object<string, number>} */
    this.votingWeights = {};
    /** @export {string} */
    this.lockdownGroup = '';
    /** @export {string} */
    this.monitorGroup = '';
    /** @export {!Object<string, (Array<string>|string)>} */
    this.rolesToSync = {};
    /**
     * @export {{
     *   message: string,
     *   severity: string,
     *   isActive: boolean,
     * }}
     */
    this.siteAlert = {'message': '', 'severity': '', 'isActive': false};
  }
};

/** Controller for settings. */
upvote.admin.settingspage.SettingsController = class {
  /**
   * @param {!upvote.admin.settings.SettingsService} settingsService
   * @param {!angular.Scope} $scope
   * @param {!angular.$window} $window
   * @param {!upvote.shared.Page} page Details about the active webpage
   * @ngInject
   */
  constructor(settingsService, $scope, $window, page) {
    /** @private {!upvote.admin.settings.SettingsService} */
    this.settingsService_ = settingsService;
    /** @private {!angular.Scope} */
    this.scope_ = $scope;
    /** @private {!angular.$window} */
    this.window_ = $window;

    /** @export {!upvote.admin.settingspage.Settings} */
    this.settings = new upvote.admin.settingspage.Settings();

    /**
     * @export {!upvote.admin.settingspage.ApiKeyStruct}
     */
    this.apiKeys = {
      'virustotal': '',
      'bit9': '',
    };

    page.title = 'Settings';

    // Initialize the controller
    this.init_();
  }

  /** @private */
  init_() {
    for (let settingName of Object.keys(this.settings)) {
      this.settingsService_.get(settingName).then((result) => {
        this.settings[settingName] = result['data'];
      });
    }
  }

  /**
   * Save the given API key's value.
   * @param {string} keyName
   * @private
   */
  saveApiKey_(keyName) {
    this.settingsService_.setApiKey(keyName, this.apiKeys[keyName])
        .then((result) => {
          this.apiKeys[keyName] = '';
        });
  }

  /**
   * Save all changes to setting values.
   * @export
   */
  saveSettings() {
    const doIt = this.window_.confirm(
        'Settings changes take effect immediately. Are you sure?');
    if (doIt) {
      if (this.scope_['virusTotalApiKey'].$dirty) {
        this.saveApiKey_('virustotal');
      }
      if (this.scope_['bit9ApiKey'].$dirty) {
        this.saveApiKey_('bit9');
      }
    }
  }
};

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

goog.provide('upvote.hostlistpage.HostListController');

goog.require('goog.i18n.DateTimeFormat');
goog.require('goog.i18n.DateTimeParse');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.ProtectionLevel');
goog.require('upvote.shared.Page');
goog.require('upvote.shared.models.AnyHost');

goog.scope(() => {

const DateTimeFormat = goog.i18n.DateTimeFormat;
const DateTimeParse = goog.i18n.DateTimeParse;
const ProtectionLevel = upvote.hosts.ProtectionLevel;

/** Controller for host page. */
upvote.hostlistpage.HostListController = class {
  /**
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active page
   * @param {!angular.$filter} $filter
   * @ngInject
   */
  constructor(hostService, errorService, $location, page, $filter) {
    /** @export {!upvote.hosts.HostService} */
    this.hostService = hostService;
    /** @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @private {!angular.$location} $location */
    this.location_ = $location;
    /** @private {!angular.$filter} $filter */
    this.filter_ = $filter;

    /** @export {?Array<?upvote.shared.models.AnyHost>} */
    this.hosts = null;

    page.title = 'Hosts';

    /** @export {boolean} */
    this.showHidden = false;

    this.init_();
  }

  /** @private */
  init_() {
    this.hostService.getAssociatedHosts()
        .then((response) => {
          this.hosts = response['data'];
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }

  /**
   * Indicates whether protection can be modified for this host.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  canModifyProtection(host) {
    return this.hostService.isSantaHost(host);
  }

  /**
   * Returns a user-friendly representation of the host's protection state.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {string}
   * @export
   */
  getProtectionText(host) {
    switch (this.hostService.getProtectionLevel(host)) {
      case ProtectionLevel.FULL:
        return 'Full Protection';
      case ProtectionLevel.DEVMODE:
        return 'Developer Mode';
      case ProtectionLevel.MINIMAL:
        let dateStr = this.filter_('date')(
            host.exemption.deactivationDt, 'EEE, MMM dd, yyyy');
        return 'Minimal Protection Until ' + dateStr;
      default:
        return 'Unknown';
    }
  }

  /**
   * Returns the CSS class of the host's current protection state.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {string}
   * @export
   */
  getProtectionClass(host) {
    switch (this.hostService.getProtectionLevel(host)) {
      case ProtectionLevel.FULL:
        return 'full-protection';
      case ProtectionLevel.DEVMODE:
        return 'developer-mode';
      case ProtectionLevel.MINIMAL:
      default:
        return 'minimal-protection';  // Fail to the scariest appearance.
    }
  }

  /**
   * Navigates to a host's "modify protection" page.
   * @param {string} hostId
   * @export
   */
  goToModifyProtectionPage(hostId) {
    this.location_.path('/hosts/' + hostId + '/modify-protection');
  }

  /**
   * Navigates to a host's "blockables" page.
   * @param {string} hostId
   * @export
   */
  goToBlockablesPage(hostId) {
    let requestPath = '/hosts/' + hostId + '/blockables';
    this.location_.path(requestPath);
  }

  /**
   * Toggles the hidden state of the host
   * @param {!upvote.shared.models.AnyHost} host
   * @export
   */
  toggleVisibility(host) {
    this.hostService.setHidden(host.id, !host.hidden)
        .then((response) => {
          host.hidden = !host.hidden;
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }
};
let HostListController = upvote.hostlistpage.HostListController;

/**
 * The number of milliseconds since a host's last sync after which it is
 * considered stale. The current limit is 30 days.
 * @export {number}
 */
HostListController.STALE_THRESHOLD = (1000 * 60 * 60 * 24) * 30;
});  // goog.scope

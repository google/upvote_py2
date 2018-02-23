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

goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.hosts.EventRateResponse');
goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.HostUtilsService');
goog.require('upvote.shared.Page');
goog.require('upvote.shared.models.AnyHost');

goog.scope(() => {

/** Controller for host page. */
upvote.hostlistpage.HostListController = class {
  /**
   * @param {!upvote.hosts.HostService} hostService
   * @param {!upvote.hosts.HostUtilsService} hostUtilsService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$location} $location
   * @param {!upvote.shared.Page} page Details about the active page
   * @ngInject
   */
  constructor(hostService, hostUtilsService, errorService, $location, page) {
    /** @private {!upvote.hosts.HostService} */
    this.hostService_ = hostService;
    /** @private {!upvote.errornotifier.ErrorService} errorService */
    this.errorService_ = errorService;
    /** @private {!angular.$location} $location */
    this.location_ = $location;

    /** @export {!upvote.hosts.HostUtilsService} */
    this.hostUtils = hostUtilsService;
    /** @export {?Array<upvote.shared.models.AnyHost>} */
    this.hosts = null;
    /** @export {!Object<string, !upvote.hosts.EventRateResponse>} */
    this.eventRates = {};

    page.title = 'Hosts';

    /** @export {boolean} */
    this.showHidden = false;

    this.init_();
  }

  /** @private */
  init_() {
    this.hostService_.getAssociatedHosts()
        .then((response) => {
          this.hosts = response['data'];
          // If there are hosts, request the event rates for each of them.
          if (!!this.hosts) {
            this.hosts.forEach((host) => {
              this.retrieveEventRate_(host);
            });
          }
        })
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }

  /**
   * Retrieve the event rate for a given host.
   * @param {!upvote.shared.models.AnyHost} host
   * @private
   */
  retrieveEventRate_(host) {
    this.hostService_.getEventRate(host['id'])
        .then((response) => {
          this.eventRates[host['id']] = response['data'];
        })
        .catch((response) => {
          this.errorService_.createToastFromError(response);
        });
  }

  /**
   * Return whether a host's mode is locked.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isModeLocked(host) {
    return !!host['clientModeLock'];
  }

  /**
   * Return whether a host's rate has been loaded.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isRateLoaded(host) {
    return !!this.eventRates[host['id']];
  }

  /**
   * Return a host's block rate or null if it hasn't loaded.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {?number}
   * @export
   */
  getRate(host) {
    if (this.isRateLoaded(host)) {
      return this.eventRates[host['id']]['avgRate'];
    } else {
      return null;
    }
  }

  /**
   * Return whether a host hasn't synced recently.
   * @param {!upvote.shared.models.AnyHost} host
   * @return {boolean}
   * @export
   */
  isStale(host) {
    let lastSync = new Date(host['ruleSyncDt']);
    if (!lastSync) {
      return true;
    }
    let secondsSinceSync = new Date().getTime() - lastSync.getTime();
    return secondsSinceSync >= HostListController.STALE_THRESHOLD;
  }

  /**
   * Navigates to a host's "request exception" page.
   * @param {!string} hostId
   * @export
   */
  goToRequestPage(hostId) {
    let requestPath = '/hosts/' + hostId + '/request-exception';
    this.location_.path(requestPath);
  }

  /**
   * Navigates to a host's "blockables" page.
   * @param {!string} hostId
   * @export
   */
  goToBlockablesPage(hostId) {
    let requestPath = '/hosts/' + hostId + '/blockables';
    this.location_.path(requestPath);
  }

  /**
   * Requests the Host be Navigates to a host's "request exception" page.
   * @param {!string} hostId
   * @export
   */
  requestLockdown(hostId) {
    this.hostService_.requestLockdown(hostId)
        .then((response) => this.init_())
        .catch((response) => {
          this.errorService_.createDialogFromError(response);
        });
  }

  /**
   * Toggles the hidden state of the host
   * @param {!upvote.shared.models.AnyHost} host
   * @export
   */
  toggleVisibility(host) {
    this.hostService_.hide(host.id, !host.hidden)
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

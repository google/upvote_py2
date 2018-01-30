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

goog.provide('upvote.listpage.BlockableListController');

goog.require('upvote.blockables.BlockableService');
goog.require('upvote.errornotifier.ErrorService');
goog.require('upvote.events.AnyEventWithContext');
goog.require('upvote.shared.Page');
goog.require('upvote.shared.models.AnyBlockable');


/** Controller for blockable list page. */
upvote.listpage.BlockableListController = class {
  /**
   * @param {!angular.Resource} eventQueryResource
   * @param {!upvote.blockables.BlockableService} blockableService
   * @param {!upvote.errornotifier.ErrorService} errorService
   * @param {!angular.$location} $location
   * @param {!angular.$q} $q
   * @param {!upvote.shared.Page} page Details about the active web page
   * @ngInject
   */
  constructor(
      eventQueryResource, blockableService, errorService, $location, $q, page) {
    /** @private {!angular.Resource} */
    this.eventQueryResource_ = eventQueryResource;
    /** @private {!upvote.blockables.BlockableService} */
    this.blockableService_ = blockableService;
    /** @protected {!upvote.errornotifier.ErrorService} */
    this.errorService = errorService;
    /** @private {!angular.$location} */
    this.location_ = $location;
    /** @private {!angular.$q} */
    this.q_ = $q;

    /** @export {number} */
    this.perPage = 10;
    /**
     * @export {!{
     *   content: Array<upvote.events.AnyEventWithContext>,
     *   more: boolean,
     *   cursor: ?string
     * }}
     */
    this.results = {'content': [], 'more': true, 'cursor': null};
    /** @export {boolean} */
    this.isLoadingMore = false;

    this.page = page;
    this.page.title = 'Applications';

    // Initialize the instance.
    this.init();
  }

  /** @protected */
  init() {
    // Load an initial page of results.
    this.loadMore();
  }

  /**
   * Loads at least `minItems` unique items.
   * @param {number} numItems The number of results that will be loaded.
   * @param {string=} opt_cursor The point in the query from which to resume
   *     loading items.
   * @return {angular.$q.Promise} A promise that resolves upon completion of the
   *     query.
   * @private
   */
  loadItems_(numItems, opt_cursor) {
    let deferred = this.q_.defer();
    let queryArgs = Object.assign(
        {'cursor': opt_cursor, 'perPage': numItems, 'withContext': true},
        this.getQueryFilters());
    this.eventQueryResource_['getPage'](queryArgs)['$promise']
        .then((newPage) => {
          let newContent = newPage['content'].filter((e) => !!e['blockable']);
          this.results['content'] = this.results['content'].concat(newContent);
          this.results['cursor'] = newPage['cursor'];
          this.results['more'] = newPage['more'];
          deferred.resolve();

          // After resolution, retrieve each blockable's pending status.
          for (let item of newContent) {
            this.blockableService_.getPending(item['blockable']['id'])
                .then((results) => {
                  item['isPending'] = results['data'];
                })
                /* Ignore all pending-state-change errors. */
                .catch((response) => {});
          }
        })
        .catch((response) => {
          this.errorService.createToastFromError(response);
          deferred.reject();
        });
    return deferred.promise;
  }

  /**
   * Loads the next page of results.
   * @export
   */
  loadMore() {
    if (this.isLoadingMore) {
      return;
    }
    this.isLoadingMore = true;
    // Unconditionally resolve the loadItems result by unsetting the
    // isLoadingMore variable.
    this.loadItems_(this.perPage, this.results['cursor'])
        .then(() => {
          this.isLoadingMore = false;
        })
        .catch(() => {
          this.isLoadingMore = false;
        });
  }

  /**
   * Return query params to add to the event query.
   * @return {!Object} An object of query params to add to the event query.
   * @protected
   */
  getQueryFilters() {
    return {};
  }

  /**
   * Returns the CSS class indicating a blockable's platform of origin.
   * @param {?upvote.shared.models.AnyBlockable} blockable The target blockable.
   * @return {string} The class string associated with the blockable's platform.
   * @export
   */
  getBlockableClass(blockable) {
    if (!blockable) {
      return '';
    }
    switch (blockable['operatingSystemFamily']) {
      case upvote.app.constants.PLATFORMS.MACOS:
        return 'santa-blockable';
      case upvote.app.constants.PLATFORMS.WINDOWS:
        return 'bit9-blockable';
      default:
        return '';
    }
  }

  /**
   * Returns the image URL associated with a blockable's platform of origin.
   * @param {?upvote.shared.models.AnyBlockable} blockable The target blockable.
   * @return {string} The URL path of the image for the blockable's platform.
   * @export
   */
  getPlatformImageUrl(blockable) {
    if (!blockable) {
      return '';
    }
    switch (blockable['operatingSystemFamily']) {
      case upvote.app.constants.PLATFORMS.MACOS:
        return '/static/images/apple_logo.svg';
      case upvote.app.constants.PLATFORMS.WINDOWS:
        return '/static/images/windows_logo.svg';
      default:
        return '';
    }
  }

  /**
   * Returns the alt text for an image associated with a blockable's platform of
   * origin.
   * @param {?upvote.shared.models.AnyBlockable} blockable The target blockable.
   * @return {string} The alt text to use for the image for the blockable's
   *    platform.
   * @export
   */
  getPlatformImageAltText(blockable) {
    if (!blockable) {
      return '';
    }
    switch (blockable['operatingSystemFamily']) {
      case upvote.app.constants.PLATFORMS.MACOS:
        return 'Mac OS Application';
      case upvote.app.constants.PLATFORMS.WINDOWS:
        return 'Windows Application';
      default:
        return '';
    }
  }

  /**
   * Navigates to the detail page for a blockable
   * @param {?upvote.shared.models.AnyBlockable} blockable The target blockable.
   * @export
   */
  goToBlockable(blockable) {
    if (!blockable) {
      this.errorService.createSimpleToast('Unknown Blockable');
    } else {
      let newPath = '/blockables/' + blockable['id'];
      this.location_.path(newPath);
    }
  }
};

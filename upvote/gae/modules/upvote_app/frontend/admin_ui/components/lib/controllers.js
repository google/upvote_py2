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

goog.provide('upvote.admin.lib.controllers.Field');
goog.provide('upvote.admin.lib.controllers.ModelController');
goog.provide('upvote.admin.lib.controllers.Platform');
goog.provide('upvote.admin.lib.controllers.Type');

goog.scope(() => {


/** @typedef {{displayName: string, value: string}} */
upvote.admin.lib.controllers.DisplayAttribute;


/** @typedef {upvote.admin.lib.controllers.DisplayAttribute} */
upvote.admin.lib.controllers.Platform;


/** @typedef {upvote.admin.lib.controllers.DisplayAttribute} */
upvote.admin.lib.controllers.Type;


/** @typedef {upvote.admin.lib.controllers.DisplayAttribute} */
upvote.admin.lib.controllers.Field;


/** Base controller for querying datastore models. */
upvote.admin.lib.controllers.ModelController = class {
  /**
   * @param {!angular.Resource} resource
   * @param {!angular.Resource} queryResource
   * @param {!angular.$routeParams} $routeParams
   * @param {!angular.Scope} $scope
   * @param {!angular.$location} $location
   */
  constructor(resource, queryResource, $routeParams, $scope, $location) {
    /** @protected {!angular.Resource} */
    this.resource = resource;
    /** @protected {!angular.Resource} */
    this.queryResource = queryResource;
    /** @protected {!angular.$routeParams} */
    this.routeParams = $routeParams;
    /** @protected {!angular.Scope} */
    this.scope = $scope;
    /** @protected {!angular.$location} */
    this.location = $location;

    /** @export {!Object<string, !upvote.admin.lib.controllers.Platform>} */
    this.platforms = angular.copy(ModelController.VALID_PLATFORMS_);
    /** @export {!Object<string, !upvote.admin.lib.controllers.Type>} */
    this.types = angular.copy(ModelController.DEFAULT_TYPES);

    /** @export {!Object} */
    this.queryData = {'search': '', 'searchBase': 'id'};
    /** @export {!Object} */
    this.requestData = {
      'platform': this.platforms['all']['value'],
      'type': this.types['all']['value'],
      'cursor': null,
      'asAdmin': true,
      'perPage': 10,
      'more': true
    };
    /** @export {!Array} */
    this.content = [];
    /** @export {!Object} */
    this.card = {};

    // Initialize view state values.
    /** @export {boolean} */
    this.showSearchBase = false;

    /** @export {string} */
    this.id = '';
  }

  /**
   * Initialization logic for constructor.
   * @protected
   */
  init() {
    this.updateOptions();
    this.loadData();

    // If an id was supplied as a route parameter, load the card.
    let idParam = this.routeParams['id'];
    if (idParam) {
      this.selectItem(idParam);
    }
  }

  /**
   * Load search query data.
   * @param {boolean=} opt_more Whether to load more items from the last query.
   * @protected
   */
  loadData(opt_more) {
    if (!opt_more) {
      this.requestData['cursor'] = null;
    }
    let data = this.queryData['search'] ?
        Object.assign({}, this.requestData, this.queryData) :
        this.requestData;
    this.queryResource['search'](data)['$promise'].then((results) => {
      this.content = opt_more ? this.content.concat(results['content']) :
                                results['content'];
      this.requestData['cursor'] = results['cursor'];
      this.requestData['more'] = results['more'];
      this.requestData['perPage'] = results['perPage'];
    });
  }

  /**
   * Load more search results from the previous query.
   * @export
   */
  loadMore() {
    this.loadData(true);
  }

  /**
   * Updates the current URL to point to the selected record.
   * @private
   */
  updateItemUrl_() {
    let currentUrl = this.location.path();

    let pathParts = currentUrl.split('/');
    // We're expecting something like: ['', 'admin', 'blockable', '']
    // But we're not sure whether there will be a fourth element
    if (pathParts.length < 4) {
      pathParts.push(this.id || '');
    } else {
      pathParts[3] = this.id || '';
    }
    let newUrl = pathParts.join('/');

    this.location.path(newUrl);
  }

  /**
   * Loads the selected record as a card.
   * @param {string} id The id of the selected item.
   * @export
   */
  selectItem(id) {
    this.id = id;
    this.updateItemUrl_();
    this.loadCard();
  }

  /**
   * Mechanism for loading single record as a card.
   * @return {?angular.$q.Promise} A promise that will resolve once the card is loaded.
   * @protected
   */
  loadCard() {
    return this.resource.get({'id': this.id})['$promise'].then((results) => {
      // Load result data into card.
      this.card = results;
      delete this.card['$promise'];

      // Add function for saving changes to data on card.
      this.card['save'] = () => {
        this.resource['update'](this.card)['$promise'].then((results) => {
          this.loadCard();
        });
      };
      // Add function to add and remove items from a list.
      this.card['toggleListMembership'] = (element, list) => {
        if (list.includes(element)) {
          list.splice(list.indexOf(element), 1);
        } else {
          list.push(element);
        }
        this.card['save']();
      };
    });
  }

  /**
   * Issues a search request with the current queryData values.
   * @export
   */
  search() {
    // If the search base is the id, just load the right card.
    if (this.queryData['searchBase'] == 'id') {
      if (this.queryData['search']) {
        this.selectItem(this.queryData['search']);
      }
    } else {
      this.loadData();
    }
  }

  /**
   * Update fields and types when platform changed to ALL
   * @export
   */
  updateToAll() {}

  /**
   * Update fields and types when platform changed to BIT9
   * @export
   */
  updateToBit9() {}

  /**
   * Update fields and types when platform changed to SANTA
   * @export
   */
  updateToSanta() {}

  /**
   * Update fields and types when platform changed.
   * @export
   */
  updateOptions() {
    let platform = this.requestData['platform'];
    if (this.platforms['all'] && platform == this.platforms['all']['value']) {
      this.updateToAll();
    } else if (
        this.platforms['bit9'] && platform == this.platforms['bit9']['value']) {
      this.updateToBit9();
    } else if (
        this.platforms['santa'] &&
        platform == this.platforms['santa']['value']) {
      this.updateToSanta();
    } else {
      this.updateToAll();
    }
  }

  /**
   * Enable searching UI.
   * @export
   */
  searchSelected() {
    this.updateOptions();
    this.showSearchBase = true;
  }
};
const ModelController = upvote.admin.lib.controllers.ModelController;

/**
 * @private @const {!Object<string, !upvote.admin.lib.controllers.Platform>}
 */
ModelController.VALID_PLATFORMS_ = {
  'all': {'displayName': 'All Platforms', 'value': ''},
  'bit9': {'displayName': 'Only Bit9', 'value': 'bit9'},
  'santa': {'displayName': 'Only Santa', 'value': 'santa'}
};

/**
 * @protected @const {!Object<string, !upvote.admin.lib.controllers.Type>}
 */
ModelController.DEFAULT_TYPES = {
  'all': {'displayName': 'All Types', 'value': ''}
};
});  // goog.scope

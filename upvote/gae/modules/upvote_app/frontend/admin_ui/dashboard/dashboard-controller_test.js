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

goog.setTestOnly();

goog.require('upvote.admin.app.constants');
goog.require('upvote.admin.blockables.module');
goog.require('upvote.admin.dashboard.DashboardController');
goog.require('upvote.errornotifier.module');


describe('Dashboard Controller', () => {
  let blockableQueryResource, errorService, location, httpBackend, q, rootScope,
      page;

  beforeEach(() => {
    module(upvote.admin.blockables.module.name);
    module(upvote.errornotifier.module.name);

    inject(
        (_blockableQueryResource_, _errorService_, $location, $httpBackend, $q,
         $rootScope) => {
          // Store injected components.
          blockableQueryResource = _blockableQueryResource_;
          errorService = _errorService_;
          location = $location;
          httpBackend = $httpBackend;
          q = $q;
          rootScope = $rootScope;
          page = {title: ''};

          // Create spies.
          spyOn(blockableQueryResource, 'search');
          errorService.createToastFromError =
              jasmine.createSpy('createToastFromError');
        });
  });

  afterEach(() => {
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('when the API calls succeed', () => {
    let expectedList = ['foo'];

    beforeEach(() => {
      let expectedResults = {'content': expectedList};
      blockableQueryResource.search.and.returnValue(
          {'$promise': q.resolve(expectedResults)});
    });

    it('should properly initialize dashboard data', () => {
      let ctrl = new upvote.admin.dashboard.DashboardController(
          blockableQueryResource, errorService, location, page);

      rootScope.$apply();

      expect(blockableQueryResource.search.calls.count()).toEqual(2);

      expect(ctrl.suspectBlockables).toEqual(expectedList);
      expect(ctrl.flaggedBlockables).toEqual(expectedList);
    });

    it('should navigate to the proper blockable on selectedItem()', () => {
      let ctrl = new upvote.admin.dashboard.DashboardController(
          blockableQueryResource, errorService, location, page);

      rootScope.$apply();

      let blockableId = 'foo';
      ctrl.onSelectedItem(blockableId);

      let expected =
          upvote.admin.app.constants.URL_PREFIX + 'blockables/' + blockableId;
      expect(location.path()).toEqual(expected);
    });
  });

  it('should create dialog on error', () => {
    blockableQueryResource.search.and.returnValue({'$promise': q.reject()});

    new upvote.admin.dashboard.DashboardController(
        blockableQueryResource, errorService, location, page);

    rootScope.$apply();

    expect(errorService.createToastFromError).toHaveBeenCalled();
    expect(blockableQueryResource.search.calls.count()).toEqual(2);
  });
});

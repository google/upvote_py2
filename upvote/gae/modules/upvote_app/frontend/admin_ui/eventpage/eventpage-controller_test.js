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

goog.require('upvote.admin.eventpage.EventController');
goog.require('upvote.admin.events.module');
goog.require('upvote.shared.Page');


describe('Event Controller', () => {
  let eventResource, eventQueryResource, routeParams, location, httpBackend, q,
      rootScope, page;

  beforeEach(() => {
    module(upvote.admin.events.module.name);

    inject(
        (_eventResource_, _eventQueryResource_, $location, $q, $httpBackend,
         $rootScope) => {
          // Store injected components.
          eventResource = _eventResource_;
          eventQueryResource = _eventQueryResource_;
          location = $location;
          httpBackend = $httpBackend;
          rootScope = $rootScope;
          q = $q;
          page = new upvote.shared.Page();

          // Create spies.
          spyOn(eventResource, 'get');
          spyOn(eventQueryResource, 'search');
          spyOn(location, 'search');

          routeParams = {'id': ''};
        });
  });

  afterEach(() => {
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  buildCtrl = () => new upvote.admin.eventpage.EventController(
      eventResource, eventQueryResource, routeParams, rootScope, location,
      page);

  describe('should make the proper API call', () => {
    beforeEach(() => {
      eventQueryResource.search.and.returnValue(
          {'$promise': q.resolve({'content': []})});
    });

    it('when no Host ID is provided', () => {
      location.search.and.returnValue({});

      let ctrl = buildCtrl();

      rootScope.$apply();

      let searchParams = eventQueryResource.search.calls.argsFor(0)[0];
      expect(searchParams['hostId']).toBeUndefined();
    });

    it('when an empty Host ID is provided', () => {
      location.search.and.returnValue({'hostId': ''});

      let ctrl = buildCtrl();

      rootScope.$apply();

      let searchParams = eventQueryResource.search.calls.argsFor(0)[0];
      expect(searchParams['hostId']).toEqual('');
    });

    it('when a Host ID is provided', () => {
      location.search.and.returnValue({'hostId': 'abc'});

      let ctrl = buildCtrl();

      rootScope.$apply();

      let searchParams = eventQueryResource.search.calls.argsFor(0)[0];
      expect(searchParams['hostId']).toEqual('abc');
    });
  });
});

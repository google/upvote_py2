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

goog.require('upvote.admin.hostpage.HostController');
goog.require('upvote.admin.hosts.module');
goog.require('upvote.errornotifier.module');
goog.require('upvote.hosts.module');
goog.require('upvote.shared.Page');


describe('HostController', () => {
  let hostResource, hostQueryResource, userResource, hostService, errorService,
      location, httpBackend, routeParams, q, rootScope, page;

  beforeEach(() => {
    module(upvote.admin.hosts.module.name);
    angular.mock.module(upvote.hosts.module.name);
    angular.mock.module(upvote.errornotifier.module.name);

    inject(
        (_hostResource_, _hostQueryResource_, _userResource_, _hostService_,
         _errorService_, $location, $httpBackend, $q, $rootScope) => {
          // Store injected components.
          hostResource = _hostResource_;
          hostQueryResource = _hostQueryResource_;
          userResource = _userResource_;
          hostService = _hostService_;
          errorService = _errorService_;
          location = $location;
          httpBackend = $httpBackend;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          spyOn(hostResource, 'get');
          spyOn(hostQueryResource, 'search');

          routeParams = {'id': ''};
        });
  });

  afterEach(() => {
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  let buildController = () => new upvote.admin.hostpage.HostController(
      hostResource, hostQueryResource, userResource, hostService, errorService,
      routeParams, rootScope, rootScope, location, page);

  beforeEach(() => {
    hostResource.get.and.returnValue(promiseValue({}));
    hostQueryResource.search.and.returnValue(promiseValue({}));
    routeParams['id'] = '';
  });

  let promiseValue = (value) => {
    return {'$promise': q.when(value)};
  };

  let promiseValueAndReject = (value) => {
    return {'$promise': q.reject(value)};
  };

  it('should update search platforms to santa', () => {
    ctrl = buildController();
    rootScope.$apply();
    expect(ctrl.fields['primary_user']).not.toBeTruthy();

    ctrl.requestData['platform'] = ctrl.platforms['santa']['value'];
    ctrl.updateOptions();

    expect(ctrl.fields['primary_user']).toBeTruthy();
  });
});

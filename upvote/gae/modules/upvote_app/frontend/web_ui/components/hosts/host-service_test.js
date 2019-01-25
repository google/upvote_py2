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

goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.Platform');
goog.require('upvote.hosts.module');

goog.scope(() => {
const HostService = upvote.hosts.HostService;


describe('Host Service', () => {
  let http, httpBackend;
  let hostService;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.hosts.module.name);

    angular.mock.inject(($http, $httpBackend) => {
      // Store injected components.
      http = $http;
      httpBackend = $httpBackend;
    });
  });

  beforeEach(() => {
    hostService = new HostService(http);
  });

  afterEach(function() {
    httpBackend.flush();
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('should request the proper URL', () => {
    it('when retrieving a host by its ID', () => {
      httpBackend.expectGET('/api/web/hosts/abc').respond(200);
      hostService.get('abc');
    });

    describe('when getting associated hosts', () => {
      it('for a given user', () => {
        httpBackend.expectGET('/api/web/hosts/associated/user@foo.com')
            .respond(200);
        hostService.getAssociatedHosts('user@foo.com');
      });

      it('for the current user', () => {
        httpBackend.expectGET('/api/web/hosts/associated').respond(200);
        hostService.getAssociatedHosts();
      });
    });

    describe('when querying for hosts', () => {
      it('related to Santa', () => {
        let qParams = {
          'perPage': '10',
          'search': 'abc',
          'searchBase': 'def',
        };
        httpBackend.whenGET(new RegExp('/api/web/hosts/query/santa?.*'))
            .respond((method, url, data, headers, params) => {
              expect(params).toEqual(qParams);
              return [200, {}];
            });

        let params =
            Object.assign({'platform': upvote.hosts.Platform.SANTA}, qParams);
        hostService.search(params);
      });
    });

    describe('when changing hidden to', () => {
      it('true', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/hidden/true').respond(200);
        hostService.setHidden('12345', true);
      });

      it('false', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/hidden/false').respond(200);
        hostService.setHidden('12345', false);
      });
    });

    describe('when changing transitive to', () => {
      it('true', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/transitive/true')
            .respond(200);
        hostService.setTransitive('12345', true);
      });

      it('false', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/transitive/false')
            .respond(200);
        hostService.setTransitive('12345', false);
      });
    });
  });
});
});  // goog.scope

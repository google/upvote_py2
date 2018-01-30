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

goog.require('upvote.errornotifier.module');
goog.require('upvote.hostrequestpage.HostRequestController');
goog.require('upvote.hosts.ExceptionReason');
goog.require('upvote.hosts.module');
goog.require('upvote.shared.Page');

goog.scope(() => {
const HostRequestController = upvote.hostrequestpage.HostRequestController;


describe('Host Request Controller', () => {
  let hostService, errorService, routeParams, q, rootScope, page;
  let ctrl;

  let fakeHost = {
    'hostname': 'foo-mbp',
    'id': '12345-12345-12345-12345',
    'primary_user': 'foo',
  };

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.errornotifier.module.name);
    angular.mock.module(upvote.hosts.module.name);
    angular.mock.module('ngRoute');

    angular.mock.inject(
        (_hostService_, _errorService_, $routeParams, $q, $rootScope) => {
          // Store injected components.
          hostService = _hostService_;
          errorService = _errorService_;
          routeParams = $routeParams;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          hostService.get = jasmine.createSpy('get');
          hostService.requestHostException =
              jasmine.createSpy('requestHostException');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          errorService.createSimpleToast =
              jasmine.createSpy('createSimpleToast');
        });
  });

  // Set the default initialization to be a fake result
  beforeEach(() => {
    hostService.get['and']['callFake'](() => q.when({'data': fakeHost}));
  });

  let buildController = () =>
      new HostRequestController(hostService, errorService, routeParams, page);

  describe('should display an error notifiction', () => {
    it('when initialization fails', () => {
      hostService.get['and']['callFake'](() => q.reject({}));

      ctrl = buildController();
      rootScope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });
  });

  describe('should initialize the host', () => {
    it('when the request succeeds', () => {
      routeParams = {'id': 'foo'};

      ctrl = buildController();
      rootScope.$apply();

      expect(hostService.get['calls'].count()).toEqual(1);
      expect(hostService.get).toHaveBeenCalledWith('foo');
      expect(ctrl['host']).toEqual(fakeHost);
      expect(ctrl['id']).toEqual('foo');
    });
  });

  it('should detect when OTHER is selected', () => {
    ctrl = buildController();
    ctrl.requestData.reason = upvote.hosts.ExceptionReason.OTHER;
    rootScope.$apply();

    expect(ctrl.isOtherSelected()).toBe(true);

    ctrl.requestData.reason = upvote.hosts.ExceptionReason.OSX_DEVELOPER;
    rootScope.$apply();

    expect(ctrl.isOtherSelected()).toBe(false);
  });

  describe('should handle submitting a request', () => {
    beforeEach(() => {
      routeParams = {'id': 'foo'};

      ctrl = buildController();
      rootScope.$apply();

      expect(hostService.get).toHaveBeenCalledWith('foo');
    });

    describe('by failing fast', () => {
      it('when there\'s no ID', () => {
        routeParams = {};

        ctrl = buildController();
        rootScope.$apply();

        ctrl.submitRequest();

        expect(errorService.createSimpleToast).toHaveBeenCalled();
      });

      it('when OTHER is selected and no explanation was provided', () => {
        ctrl.requestData.reason = upvote.hosts.ExceptionReason.OTHER;
        ctrl.requestData.otherText = '';

        ctrl.submitRequest();

        expect(errorService.createSimpleToast).toHaveBeenCalled();
      });
    });

    describe('by submitting the request', () => {
      afterEach(() => {
        expect(hostService.requestHostException).toHaveBeenCalled();
      });

      describe('but failing upon submission', () => {
        afterEach(() => {
          expect(ctrl.requested).toBe(false);
        });

        it('when there is an existing request', () => {
          hostService.requestHostException['and']['returnValue'](
              q.reject({'status': 409}));

          ctrl.submitRequest();
          rootScope.$apply();

          expect(errorService.createSimpleToast).toHaveBeenCalled();
        });

        it('when there is an unhandled error', () => {
          hostService.requestHostException['and']['returnValue'](
              q.reject({'status': 400}));

          ctrl.submitRequest();
          rootScope.$apply();

          expect(errorService.createDialogFromError).toHaveBeenCalled();
        });
      });

      it('and succeeding when all requirements are met', () => {
        hostService.requestHostException['and']['returnValue'](q.resolve({}));

        ctrl.submitRequest();
        rootScope.$apply();

        expect(ctrl.requested).toBe(true);
        expect(errorService.createSimpleToast).not.toHaveBeenCalled();
        expect(errorService.createDialogFromError).not.toHaveBeenCalled();
      });
    });
  });
});
});  // goog.scope

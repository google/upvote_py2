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
goog.require('upvote.events.module');
goog.require('upvote.hostblockablespage.HostBlockableListController');
goog.require('upvote.hosts.module');
goog.require('upvote.shared.Page');

goog.scope(() => {
const HostBlockableListCtrl =
    upvote.hostblockablespage.HostBlockableListController;


describe('Host Blockable List Controller', () => {
  let eventQueryResource, blockableService, hostService, errorService, location,
      q, rootScope, page;
  let ctrl;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.blockables.module.name);
    angular.mock.module(upvote.events.module.name);
    angular.mock.module(upvote.hosts.module.name);
    angular.mock.module(upvote.errornotifier.module.name);

    angular.mock.inject(
        (_eventQueryResource_, _blockableService_, _hostService_,
         _errorService_, $location, $q, $rootScope) => {
          // Store injected components.
          eventQueryResource = _eventQueryResource_;
          blockableService = _blockableService_;
          hostService = _hostService_;
          errorService = _errorService_;
          location = $location;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          spyOn(eventQueryResource, 'getPage');
          blockableService.getPending = jasmine.createSpy('getPending');
          hostService.get = jasmine.createSpy('get');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          errorService.createSimpleToast =
              jasmine.createSpy('createSimpleToast');
        });
  });

  // Set the default initialization to be one without results
  beforeEach(() => {
    setEvent({
      'content': [],
      'cursor': 'foo',
      'more': false,
    });
    setHost({'id': 'foo', 'hostname': 'bar'});
    setPendingState(false);
  });

  let setPendingState = (isPending) => {
    if (isPending != null) {
      blockableService.getPending['and']['returnValue'](
          q.resolve({'data': isPending}));
    } else {
      blockableService.getPending['and']['returnValue'](q.reject());
    }
  };

  let buildController = (routeParams) => new HostBlockableListCtrl(
      eventQueryResource, blockableService, hostService, errorService, location,
      q, routeParams, page);

  let setEvent = (event_) => {
    if (event_ != null) {
      eventQueryResource['getPage']['and']['returnValue'](
          {'$promise': q.when(event_)});
    } else {
      eventQueryResource['getPage']['and']['returnValue'](
          {'$promise': q.reject()});
    }
  };

  let setHost = (host_) => {
    if (host_ != null) {
      hostService.get['and']['returnValue'](q.when({'data': host_}));
    } else {
      hostService.get['and']['returnValue'](q.reject());
    }
  };

  describe('should display an error notifiction', () => {
    it('when no host ID provided', () => {
      ctrl = buildController({});
      rootScope.$apply();

      expect(errorService.createSimpleToast).toHaveBeenCalled();
    });

    it('when host initialization fails', () => {
      setHost(null);

      ctrl = buildController({'hostId': 'foo'});
      rootScope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });
  });

  it('should fetch the host', () => {
    ctrl = buildController({'hostId': 'foo'});
    rootScope.$apply();

    expect(hostService.get['calls'].count()).toEqual(1);
    expect(ctrl.host['id']).toEqual('foo');
  });

  it('should result in the host id being a query arg', () => {
    ctrl = buildController({'hostId': 'foo'});
    rootScope.$apply();

    expect(eventQueryResource['getPage']).toHaveBeenCalledWith({
      'cursor': null,
      'perPage': 10,
      'withContext': true,
      'hostId': 'foo'
    });
  });
});
});  // goog.scope

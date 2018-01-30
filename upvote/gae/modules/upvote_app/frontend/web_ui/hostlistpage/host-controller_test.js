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
goog.require('upvote.hostlistpage.HostListController');
goog.require('upvote.hosts.module');
goog.require('upvote.shared.Page');

goog.scope(() => {
const HostListController = upvote.hostlistpage.HostListController;


describe('Host List Controller', () => {
  let hostService, errorService, location, q, rootScope, page;
  let ctrl;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.errornotifier.module.name);
    angular.mock.module(upvote.hosts.module.name);

    angular.mock.inject(
        (_hostService_, _errorService_, $location, $q, $rootScope) => {
          // Store injected components.
          hostService = _hostService_;
          errorService = _errorService_;
          location = $location;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          hostService.getAssociatedHosts =
              jasmine.createSpy('getAssociatedHosts');
          hostService.getEventRate = jasmine.createSpy('getEventRate');
          hostService.requestLockdown = jasmine.createSpy('requestLockdown');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          errorService.createToastFromError =
              jasmine.createSpy('createToastFromError');
        });
  });

  let setHosts = (hosts) => {
    if (hosts != null) {
      hostService.getAssociatedHosts['and']['returnValue'](
          q.resolve({'data': hosts}));
    } else {
      hostService.getAssociatedHosts['and']['returnValue'](q.reject());
    }
  };

  // Set the default initialization to be one without results
  beforeEach(() => {
    setHosts([]);
    hostService.getEventRate['and']['returnValue'](
        q.resolve({'data': {'avgRate': 0.1}}));
  });

  let buildController = () =>
      new HostListController(hostService, errorService, location, page);

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getHost = (opt_properties) =>
      Object.assign({'id': 'foo', 'class_': ['Host']}, opt_properties);

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getBit9Host = (opt_properties) =>
      Object.assign(getHost({'class_': ['Host', 'Bit9Host']}), opt_properties);

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getSantaHost = (opt_properties) =>
      Object.assign(getHost({'class_': ['Host', 'SantaHost']}), opt_properties);

  describe('should display an error notifiction', () => {
    it('when host initialization fails', () => {
      setHosts(null);

      ctrl = buildController();
      rootScope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });

    it('when event rate initialization fails', () => {
      setHosts([{'id': 'foo'}]);
      hostService.getEventRate['and']['returnValue'](q.reject({}));

      ctrl = buildController();
      rootScope.$apply();
      rootScope.$apply();

      expect(errorService.createToastFromError).toHaveBeenCalled();
    });
  });

  describe('should initialize the host list', () => {
    it('when there are no results', () => {
      ctrl = buildController();
      rootScope.$apply();
      rootScope.$apply();

      expect(hostService.getAssociatedHosts['calls'].count()).toEqual(1);
      expect(hostService.getEventRate['calls'].count()).toEqual(0);
      expect(ctrl.hosts).toEqual([]);
    });

    it('when there are results', () => {
      let hosts = [getSantaHost({'id': 'foo'}), getSantaHost({'id': 'bar'})];
      setHosts(hosts);
      hostService.getEventRate['and']['returnValue'](
          q.resolve({'data': {'avgRate': 0.1}}));
      ctrl = buildController();
      rootScope.$apply();
      rootScope.$apply();

      expect(hostService.getAssociatedHosts['calls'].count()).toEqual(1);
      expect(hostService.getEventRate['calls'].count()).toEqual(2);
      expect(ctrl.hosts).toEqual(hosts);
      expect(ctrl.eventRates['foo']['avgRate']).toEqual(.1);
      expect(ctrl.eventRates['bar']['avgRate']).toEqual(.1);
    });
  });

  describe('should reflect the proper host type', () => {
    beforeEach(() => {
      ctrl = buildController();
      rootScope.$apply();
    });

    it('for Santa hosts', () => {
      let fakeHost = getSantaHost();

      expect(ctrl.isSantaHost(fakeHost)).toBe(true);
      expect(ctrl.isBit9Host(fakeHost)).toBe(false);
    });

    it('for Bit9 hosts', () => {
      let fakeHost = getBit9Host();

      expect(ctrl.isSantaHost(fakeHost)).toBe(false);
      expect(ctrl.isBit9Host(fakeHost)).toBe(true);
    });

    it('for other hosts', () => {
      let fakeHost = getHost();

      expect(ctrl.isSantaHost(fakeHost)).toBe(false);
      expect(ctrl.isBit9Host(fakeHost)).toBe(false);
    });
  });

  describe('should return', () => {
    beforeEach(() => {
      ctrl = buildController();
      rootScope.$apply();
    });

    describe('whether the Host is in lockdown mode', () => {
      describe('for a Santa host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getSantaHost({'clientMode': 'LOCKDOWN'});

          expect(ctrl.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getSantaHost({'clientMode': 'not anything'});

          expect(ctrl.isInLockdown(fakeHost)).toBe(false);
        });
      });

      describe('for a Bit9 host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'LOCKDOWN'});

          expect(ctrl.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'nothing'});

          expect(ctrl.isInLockdown(fakeHost)).toBe(false);
        });
      });
    });

    it('false for unexpected host types', () => {
      let fakeHost = getHost({'clientMode': 'LOCKDOWN'});

      expect(ctrl.isInLockdown(fakeHost)).toBe(false);
    });
  });

  describe('should return whether a Host is stale', () => {
    beforeEach(() => {
      ctrl = buildController();
      rootScope.$apply();
    });

    it('when it is stale', () => {
      let fourtyFiveDaysAgo =
          new Date().getTime() - 1.5 * HostListController.STALE_THRESHOLD;
      let fourtyFiveDaysAgoString = new Date(fourtyFiveDaysAgo).toISOString();
      let fakeHost = getHost({'ruleSyncDt': fourtyFiveDaysAgoString});

      expect(ctrl.isStale(fakeHost)).toBe(true);
    });

    it('when it has never synced', () => {
      let fakeHost = getHost({'ruleSyncDt': null});

      expect(ctrl.isStale(fakeHost)).toBe(true);
    });

    it('when it is fresh', () => {
      let fakeHost = getHost({'ruleSyncDt': new Date().toISOString()});

      expect(ctrl.isInLockdown(fakeHost)).toBe(false);
    });
  });

  describe('should navigate to the request page', () => {
    it('when provided with a valid ', () => {
      ctrl = buildController();
      ctrl.goToRequestPage('abc');
      rootScope.$apply();

      expect(location.path()).toEqual('/hosts/abc/request-exception');
    });
  });

  describe('should navigate to the blockable page', () => {
    it('when provided with a valid ', () => {
      ctrl = buildController();
      ctrl.goToBlockablesPage('abc');
      rootScope.$apply();

      expect(location.path()).toEqual('/hosts/abc/blockables');
    });
  });

  describe('for lockdown requests,', () => {
    beforeEach(() => {
      setHosts([getSantaHost({'clientMode': 'foo'})]);

      ctrl = buildController();
      rootScope.$apply();
    });

    it('when the request succeeds, the hosts should be refreshed', () => {
      // Update the client mode.
      let host = getSantaHost({'id': 'foo', 'clientMode': 'bar'});
      setHosts([host]);
      hostService.requestLockdown['and']['returnValue'](q.resolve(host));

      ctrl.requestLockdown('foo');
      rootScope.$apply();

      expect(hostService.requestLockdown).toHaveBeenCalledWith('foo');
      expect(hostService.getAssociatedHosts['calls'].count()).toEqual(2);
      // Verify that the client mode has changed.
      expect(ctrl.hosts[0]['clientMode']).toEqual('bar');
    });

    it('when the request fails, an error dialog should be shown', () => {
      hostService.requestLockdown['and']['returnValue'](q.reject({}));

      ctrl.requestLockdown('foo');
      rootScope.$apply();

      expect(hostService.requestLockdown).toHaveBeenCalledWith('foo');
      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });
  });
});
});  // goog.scope

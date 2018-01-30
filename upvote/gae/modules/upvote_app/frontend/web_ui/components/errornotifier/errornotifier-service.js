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

goog.provide('upvote.errornotifier.ErrorService');

goog.require('goog.Uri');

goog.scope(() => {


/** Provides a quick way of communicating an error to the user. */
upvote.errornotifier.ErrorService = class {
  /**
   * @param {md.$dialog} $mdDialog
   * @param {md.$toast} $mdToast
   * @ngInject
   */
  constructor($mdDialog, $mdToast) {
    /** @private {md.$dialog} */
    this.mdDialog_ = $mdDialog;
    /** @private {md.$toast} */
    this.mdToast_ = $mdToast;
  }

  /**
   * Constructs the full URL present in `errorConfig`.
   * @param {angular.$http.Config} errorConfig The config returned by the $http
   *     call that encountered an error.
   * @return {string} The URL (with query params) for the provided `errorConfig`
   * @private
   */
  getHttpErrorUrl_(errorConfig) {
    let requestUri = new goog.Uri(errorConfig['config']['url']);
    let params = errorConfig['config']['params'];
    if (params) {
      Object.keys(params).map(
          (key, index, array) =>
              requestUri.setParameterValue(key, params[key]));
    }
    return requestUri.toString();
  }

  /**
   * Generates and displays a toast communicating an error.
   * @param {string} text The text of the dialog.
   * @export
   */
  createSimpleToast(text) {
    let toast = this.mdToast_.simple()
                    .position('top right')
                    .textContent(text)
                    .hideDelay(ErrorService.TOAST_DELAY_);
    this.mdToast_.show(toast);
  }

  /**
   * Generates and displays a toast with the option of getting additional info.
   * @param {string} text The text of the dialog.
   * @param {function(string)} toastCallback The action to be called upon
   *     dismissal of the toast.
   * @export
   */
  createMoreInfoToast(text, toastCallback) {
    let toast = this.mdToast_.simple()
                    .position('top right')
                    .textContent(text)
                    .action('MORE INFO')
                    .highlightAction(true)
                    .hideDelay(ErrorService.TOAST_DELAY_);
    this.mdToast_.show(toast).then(toastCallback);
  }

  /**
   * Generates and displays a toast communicating an HTTP error.
   * @param {angular.$http.Config|Error} error Either a config returned by a
   *     failed $http call, or an actual Error.
   * @export
   */
  createToastFromError(error) {
    let errorSummary = 'Error Encountered';
    if (error.status && error.statusText) {
      errorSummary = `HTTP Error ${error.status} ${error.statusText}`;
    }

    this.createMoreInfoToast(errorSummary, (response) => {
      if (response == 'ok') {
        this.createDialogFromError(error);
      }
    });
  }

  /**
   * Generates and displays a dialog communicating an error.
   * @param {string} title The title text of the dialog.
   * @param {string} body The body text of the dialog. WARNING: Parsed as HTML.
   *     Do not allow user to control this field!!
   * @export
   */
  createDialog(title, body) {
    this.mdDialog_.show(
        this.mdDialog_.alert().title(title).htmlContent(body).ok('OK'));
  }

  /**
   * Generates and displays a dialog communicating an error.
   * @param {angular.$http.Config|Error} error Either a config returned by a
   *     failed $http call, or an actual Error.
   * @export
   */
  createDialogFromError(error) {
    // Start out with some default text.
    let title = 'Error Encountered';
    let errorBody = 'An unexpected error has occurred.';

    if (error.status && error.statusText) {
      // Handle configs returned by failed $http calls.
      title = `HTTP Error ${error.status} ${error.statusText}`;
      let requestUrl = this.getHttpErrorUrl_(error);
      let body = error['data'];
      errorBody = `URL: ${requestUrl}<br>Message: ${body}`;
      this.createDialog(title, errorBody);
    } else if (error.message) {
      // Handle built-in Error types.
      errorBody = error.message;
    }

    this.createDialog(title, errorBody);
  }
};
let ErrorService = upvote.errornotifier.ErrorService;

/** @private {number} */
ErrorService.TOAST_DELAY_ = 5000;  // 5 seconds
});                                // goog.scope

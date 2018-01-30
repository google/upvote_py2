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

goog.provide('upvote.packagecontents.CertIconController');


upvote.packagecontents.CertIconController = class {
  constructor() {
    /** @export {string} */
    this.packageCertId;
    /** @export {string} */
    this.binaryCertId;
  }

  /**
   * Whether the package has a code signature.
   * @return {boolean}
   * @export
   */
  isPackageSigned() {
    return !!this.packageCertId;
  }

  /**
   * Whether the binary has a code signature.
   * @return {boolean}
   * @export
   */
  isBinarySigned() {
    return !!this.binaryCertId;
  }

  /**
   * Whether the binary and package signatures conflict.
   * @return {boolean}
   * @export
   */
  isMismatch() {
    return this.isPackageSigned() && this.isBinarySigned() &&
        this.packageCertId != this.binaryCertId;
  }

  /**
   * Return the description of the signature state of the binary.
   * @return {string}
   * @export
   */
  getStatusText() {
    if (this.isMismatch()) {
      return 'Signature Mismatch';
    } else if (this.isBinarySigned()) {
      if (this.isPackageSigned()) {
        return 'Valid Signature';
      } else {
        return 'Package not signed';
      }
    } else {
      return 'Not Signed';
    }
  }

  /**
   * Return the class to attach to the icon.
   * @return {string}
   * @export
   */
  getClass() {
    if (this.isMismatch()) {
      return 'uv-error';
    } else if (this.isBinarySigned() && this.isPackageSigned()) {
      return 'uv-success';
    } else {
      // If either the package or the binary aren't signed, we have no strong
      // signal on the quality of the signature so display a neutral icon.
      return '';
    }
  }
};

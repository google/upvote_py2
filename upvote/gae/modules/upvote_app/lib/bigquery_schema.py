# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""List of constants for BigQueryRow SchemaField ordering."""

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery as bq

from upvote.shared import constants

_BQ_TYPE = constants.UppercaseNamespace(
    ['STRING', 'TIMESTAMP', 'BOOLEAN', 'INTEGER'])

_BQ_MODE = constants.UppercaseNamespace(['REPEATED', 'NULLABLE', 'REQUIRED'])

INSERT_ID_FIELD = bq.SchemaField(name='insert_id', field_type=_BQ_TYPE.STRING)

VOTE = [
    bq.SchemaField(name='sha256', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='upvote', field_type=_BQ_TYPE.BOOLEAN),
    bq.SchemaField(name='weight', field_type=_BQ_TYPE.INTEGER),
    bq.SchemaField(name='platform', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='target_type', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='voter', field_type=_BQ_TYPE.STRING)]

HOST = [
    bq.SchemaField(name='device_id', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='hostname', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='platform', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(
        name='users', field_type=_BQ_TYPE.STRING, mode=_BQ_MODE.REPEATED),
    bq.SchemaField(name='mode', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

BINARY = [
    bq.SchemaField(name='sha256', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='state', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='score', field_type=_BQ_TYPE.INTEGER),
    bq.SchemaField(name='platform', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='client', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='first_seen_file_name', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='cert_fingerprint', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

EXECUTION = [
    bq.SchemaField(name='sha256', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='device_id', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='platform', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='client', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='bundle_path', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='file_path', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='file_name', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='executing_user', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(
        name='associated_users', field_type=_BQ_TYPE.STRING,
        mode=_BQ_MODE.REPEATED),
    bq.SchemaField(name='decision', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

CERTIFICATE = [
    bq.SchemaField(name='fingerprint', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='common_name', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='organization', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='organizational_unit', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='not_before', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='not_after', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='state', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='score', field_type=_BQ_TYPE.INTEGER),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

BUNDLE = [
    bq.SchemaField(name='bundle_hash', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='bundle_id', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='version', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='state', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='score', field_type=_BQ_TYPE.INTEGER),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

BUNDLE_BINARY = [
    bq.SchemaField(name='bundle_hash', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='sha256', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='cert_fingerprint', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='relative_path', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='file_name', field_type=_BQ_TYPE.STRING)]

USER = [
    bq.SchemaField(name='email', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(name='timestamp', field_type=_BQ_TYPE.TIMESTAMP),
    bq.SchemaField(name='action', field_type=_BQ_TYPE.STRING),
    bq.SchemaField(
        name='roles', field_type=_BQ_TYPE.STRING, mode=_BQ_MODE.REPEATED),
    bq.SchemaField(name='comment', field_type=_BQ_TYPE.STRING)]

TABLE_SCHEMAS = {
    constants.GAE_STREAMING_TABLES.VOTE: VOTE,
    constants.GAE_STREAMING_TABLES.HOST: HOST,
    constants.GAE_STREAMING_TABLES.BINARY: BINARY,
    constants.GAE_STREAMING_TABLES.EXECUTION: EXECUTION,
    constants.GAE_STREAMING_TABLES.CERTIFICATE: CERTIFICATE,
    constants.GAE_STREAMING_TABLES.BUNDLE: BUNDLE,
    constants.GAE_STREAMING_TABLES.BUNDLE_BINARY: BUNDLE_BINARY,
    constants.GAE_STREAMING_TABLES.USER: USER}

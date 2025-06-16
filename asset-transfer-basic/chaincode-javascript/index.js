/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const assetTransfer = require('./lib/assetTransfer');
const accessControl = require('./lib/accessControl');

module.exports.AssetTransfer = assetTransfer;
module.exports.AccessControl = accessControl;
module.exports.contracts = [assetTransfer, accessControl];

#!/bin/sh -e
set -xe

################################################################################
# This program and the accompanying materials are made available under the terms of the
# Eclipse Public License v2.0 which accompanies this distribution, and is available at
# https://www.eclipse.org/legal/epl-v20.html
#
# SPDX-License-Identifier: EPL-2.0
#
# Copyright Contributors to the Zowe Project.
################################################################################

# constants
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(pwd)

# build
echo "$SCRIPT_NAME building keyring ..."

cd content/build

. ./build.sh

# cleanup build results
cd "$SCRIPT_DIR"

mv content bk/
mkdir -p content
cp bk/build/keyring-util content/
cp bk/manifest.yaml content/

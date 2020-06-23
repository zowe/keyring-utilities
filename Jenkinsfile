#!groovy

/**
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright IBM Corporation 2018, 2019
 */




node('ibm-jenkins-slave-nvm') {

    def lib = library("jenkins-library").org.zowe.jenkins_shared_library

    def pipeline = lib.pipelines.generic.GenericPipeline.new(this)
    pipeline.admins.add("markackert")

    pipeline.setup(
        packageName: 'org.zowe.keyring-utilities',
        extraInit: {
            def packageJson = readJSON(file: 'package.json')
            def version

            if (env.BRANCH_NAME != "master") {
                version = packageJson['version'] + "-SNAPSHOT"
            }
            else {
                version = packageJson['version']
            }
            pipeline.setVersion(version)
        }
    )

    pipeline.build(
        operation: {
            echo "Build will happen in pre-packaging"
        }
    )

    // define we need packaging stage, which processed in .pax folder
    pipeline.packaging(name: 'keyring', extraFiles: 'keyring-util')

    // define we need publish stage
    pipeline.publish(
        allowPublishWithoutTest: true,
        artifacts: [
            '.pax/keyring-util',
        ]
    )

    pipeline.end()

}

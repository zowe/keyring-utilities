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

 /* def PAX_SERVER_HOST        = 'zzow01.zowe.marist.cloud'
  def PAX_SERVER_PORT        = 22
  def PAX_SERVER_CREDENTIAL  = 'ssh-marist-server-zzow01'
  def PAX_PACKAGING_REMOTE_WORKSPACE = '/ZOWE/tmp'
*/

  def lib = library("jenkins-library").org.zowe.jenkins_shared_library

  def pipeline = lib.pipelines.generic.GenericPipeline.new(this)
  pipeline.admins.add("markackert")
    
 /* def packageJson = readJSON(file: 'package.json')
  def version

  if (env.BRANCH_NAME != "master") {
      version = packageJson['version'] + "-SNAPSHOT"
  }
  else {
      version = packageJson['version']
  }
*/ 
  pipeline.setup(
      packageName: 'org.zowe.keyring-utilities',
      extraInit: {
          pipeline.setVersion("1.0.1")
      }
  )
/* If zSS style doesn't work, manual commands
  pipeline.build(
      operation: {
        ansiColor('xterm') {
            def remoteWorkspaceFullPath = "${PAX_PACKAGING_REMOTE_WORKSPACE}/keyring-utilities/${env.BRANCH_NAME}-${env.BUILD_NUMBER}"
            usernamePassword(
                credentialsId: PAX_SERVER_CREDENTIAL,
                passwordVariable: "PASSWORD",
                usernameVariable: "USERNAME"
            )

            // make tar to ship source over
            sh "tar -cf keyring.tar ./*"

            //make dir if it doesn't exist
            sh """SSHPASS=\${PASSWORD} sshpass -e sftp -o BatchMode=no -o StrictHostKeyChecking=no -P ${this.sshPort} -b - \${USERNAME}@${this.sshHost} << EOF
mkdir -p ${remoteWorkspaceFullPath}
EOF"""

            // ship tar      
            sh """SSHPASS=\${PASSWORD} sshpass -e sftp -o BatchMode=no -o StrictHostKeyChecking=no -P ${this.sshPort} -b - \${USERNAME}@${this.sshHost} << EOF
put keyring.tar ${remoteWorkspace}
EOF"""

            // extract tar
            sh """SSHPASS=\${PASSWORD} sshpass -e ssh -tt -o StrictHostKeyChecking=no -p ${this.PAX_SERVER_PORT} \${USERNAME}@${this.PAX_SERVER_HOST} << EOF
cd ${remoteWorkspaceFullPath}
tar -xf keyring.tar
EOF"""

             // run build tar
            sh """SSHPASS=\${PASSWORD} sshpass -e ssh -tt -o StrictHostKeyChecking=no -p ${this.PAX_SERVER_PORT} \${USERNAME}@${this.PAX_SERVER_HOST} << EOF
npm install && npm run prebuild
EOF"""
        }
      }
  )
*/
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

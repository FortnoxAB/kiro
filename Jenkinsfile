#!/usr/bin/env groovy

node('python311') {
    container('run') {
        def tag = ''
        def gitTag = ''
        boolean createdTag = false

        try {
            stage('Checkout') {
                checkout scm
                gitTag = sh(script: 'git tag -l --contains HEAD', returnStdout: true).trim()
            }

            if (gitTag != '') {
                tag = gitTag
            }else if (env.BRANCH_NAME == 'main') {
                stage('create tag') {
                    sshagent(credentials: ['jenkins-kiro-github']) {
                        tag = sh(
                                script: 'fnxctl git bump-tag',
                                returnStdout: true
                        ).trim()
                    }
                    createdTag = true
                    echo 'new tag: ' + tag
                }
            }

            if (tag != '') {
                stage('Generate and push docker image') {
                    echo "Building with docker tag ${tag}"
                    docker.withRegistry('https://quay.io', 'docker-registry') {
                        sh("fnxctl build backend ${tag}")
                    }
                }
                stage('Trigger deploy to dev') {
					build job: 'infosec/kiro/deploy-dev', parameters: [
							[$class: 'StringParameterValue', name: 'GIT_TAG', value: gitTag]
					], wait: false
				}
            }
        } catch (err) {
            if (createdTag) {
                sshagent(credentials: ['jenkins-kiro-github']) {
                    sh("git tag -d ${tag}")
                    sh("git push --delete origin ${tag}")
                }
            }
            throw err
        }
    }
}

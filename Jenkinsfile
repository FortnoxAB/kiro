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
                    sshagent(credentials: ['18270936-0906-4c40-a90e-bcf6661f501d']) {
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
            }
        } catch (err) {
            if (createdTag) {
                sshagent(credentials: ['18270936-0906-4c40-a90e-bcf6661f501d']) {
                    sh("git tag -d ${tag}")
                    sh("git push --delete origin ${tag}")
                }
            }
            throw err
        }
    }
}

#!/bin/bash
set -x
set -e 
set -o pipefail

# ISO_PATH=/media/data/fuel-5.1.1-28-2014-11-20_21-01-00.iso
# TMP_FOLDER=/media/fuel_remake_iso

ISO_PATH=$1
TMP_FOLDER=$2

CERT_SCRIPT_GIT_URL=https://github.com/stgleb/fuel-web.git
TEST_GIT_URL=https://github.com/stgleb/fuel-main
# CERT_PATH_ORIGIN=~/workspace/fsert/certification_script/certification_script
# TEST_PATH_ORIGIN=~/workspace/fsert/fuel-main/fuelweb_test/tests

CERT_PATH_GIT="$TMP_FOLDER/cert_script_git"
TEST_PATH_GIT="$TMP_FOLDER/tests_git"

CERT_BRANCH="sertification-script"
TEST_BRANCH="certification"

CERT_PATH="$TMP_FOLDER/certification_script"
TEST_PATH="$TMP_FOLDER/fuelweb_tests"
ISO_MNT_FOLDER="$TMP_FOLDER/old_iso_mount"
DOCKER_IMAGES_FOLDER="$TMP_FOLDER/container_images"
DOCKER_IMAGE="$ISO_MNT_FOLDER/docker/images/fuel-images.tar.lrz"
NEW_DOCKER_IMAGE="$DOCKER_IMAGES_FOLDER/fuel-images.tar.lrz"
WHOLE_TAR_FILE="$DOCKER_IMAGES_FOLDER/fuel-images.tar"
NAILGUIN_TAR_FILE="$DOCKER_IMAGES_FOLDER/nailgun.tar"
NAILGUN_CONTAINER_TMP_FOLDER="$DOCKER_IMAGES_FOLDER/nailgun"
NAILGUN_CONTENT_TMP_FOLDER="$DOCKER_IMAGES_FOLDER/nailgun_fs"
IMAGE_SCRIPT_FOLDER="$NAILGUN_CONTENT_TMP_FOLDER/usr/lib/python2.6/site-packages"
WHOLE_ISO_TMP="$TMP_FOLDER/image"
SCRIPTS_TMP_FOLDER_FOR_DOCKER="$TMP_FOLDER/files"
RESULT_ISO="$TMP_FOLDER/fuel_cert_iso.iso"
MIN_FREE_SPACE=13728640
DEVOPS_GIT_FOLDER="$TMP_FOLDER/devops_git"

function remote_old_nailgun_container() {
    set +e 
    set +o pipefail
    NAILGUN_IMAGE_ID=`docker images | grep nailgun | awk '{print $3}'`
    set -e 
    set -o pipefail
    
    if [ ! -z "$NAILGUN_IMAGE_ID" ] ; then
        docker rmi $NAILGUN_IMAGE_ID
    fi    
}

function test_environment() {
    if [ ! -f "$ISO_PATH" ]; then
        echo "ERROR: Base iso file not found at $ISO_PATH"
        exit 1
    fi

    set +e 
    set +o pipefail

    which lrunzip > /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: Can't found lrunzip. Install it with sudo apt-get install lrunzip"
        exit 1
    fi

    which docker > /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: Can't found docker. Install it with sudo apt-get install docker.io, add youself to docker group and relogin"
        exit 1
    fi

    which git > /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: Can't found git. Install it with sudo apt-get install git"
        exit 1
    fi

    docker images > /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: 'docker images' failed"
        exit 1
    fi

    which mkisofs > /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: Can't found mkisofs"
        exit 1
    fi

    # check free space
    TMP_FREE_SPACE=`df -k "$TMP_FOLDER" | tail -n1 | awk '{print $4}'`
    if [ "$TMP_FREE_SPACE" -lt "$MIN_FREE_SPACE" ] ; then
        echo "At least 1024 * $MIN_FREE_SPACE free space required, but only $TMP_FREE_SPACE available. Free some space and restart"
        exit 1
    fi

    set -e 
    set -o pipefail
}

function checkout_code() {
    set +e 
    rm -rf "$CERT_PATH"
    rm -rf "$TEST_PATH"
    rm -rf "$CERT_PATH_GIT"
    rm -rf "$TEST_PATH_GIT"
    rm -rf "$DEVOPS_GIT_FOLDER"
    set -e 

    mkdir -p "$CERT_PATH"
    mkdir -p "$TEST_PATH"
    mkdir -p "$CERT_PATH_GIT"
    mkdir -p "$TEST_PATH_GIT"
    mkdir -p "$DEVOPS_GIT_FOLDER"

    git clone -b "$CERT_BRANCH" --single-branch "$CERT_SCRIPT_GIT_URL" "$CERT_PATH_GIT"
    git clone -b "$TEST_BRANCH" --single-branch "$TEST_GIT_URL" "$TEST_PATH_GIT"
    git clone https://github.com/stackforge/fuel-devops.git "$DEVOPS_GIT_FOLDER"

    CERT_PATH_ORIGIN="$CERT_PATH_GIT/certification_script"
    TEST_PATH_ORIGIN="$TEST_PATH_GIT/fuelweb_test"

    cp -r "$CERT_PATH_ORIGIN/." "$CERT_PATH"
    cp -r "$TEST_PATH_ORIGIN/." "$TEST_PATH"
}

function repack_containers_archive() {
    rm -f "$WHOLE_TAR_FILE"
    pushd $TMP_FOLDER/container_images
    sudo tar -cf "$WHOLE_TAR_FILE" *.tar
    popd

    rm -f "$NEW_DOCKER_IMAGE"
    lrzip "$WHOLE_TAR_FILE" -o "$NEW_DOCKER_IMAGE"    
}

function using_docker_file() {

    docker load -i "$NAILGUIN_TAR_FILE"
    NAILGUN_IMAGE_NAME=`docker images | grep nailgun | awk '{print $1}'`

    CERT_PATH_DIR_NAME=`basename $CERT_PATH`
    TEST_PATH_DIR_NAME=`basename $TEST_PATH`
    DEVOPS_DIR_NAME=$(basename $DEVOPS_GIT_FOLDER)

    cp -r "$CERT_PATH" "$SCRIPTS_TMP_FOLDER_FOR_DOCKER"
    cp -r "$TEST_PATH" "$SCRIPTS_TMP_FOLDER_FOR_DOCKER"
    cp -r "$DEVOPS_GIT_FOLDER" "$SCRIPTS_TMP_FOLDER_FOR_DOCKER"

    DOCKERFILE=$SCRIPTS_TMP_FOLDER_FOR_DOCKER/Dockerfile
    echo "FROM $NAILGUN_IMAGE_NAME" > $DOCKERFILE
    

    REQ_FILE="/usr/lib/python2.6/site-packages/$TEST_PATH_DIR_NAME/requirements.txt"

    echo "COPY $CERT_PATH_DIR_NAME /usr/lib/python2.6/site-packages/$CERT_PATH_DIR_NAME" >> $DOCKERFILE
    echo "COPY $TEST_PATH_DIR_NAME /usr/lib/python2.6/site-packages/$TEST_PATH_DIR_NAME" >> $DOCKERFILE
    echo "COPY $DEVOPS_DIR_NAME /tmp/$DEVOPS_DIR_NAME" >> $DOCKERFILE
    echo "WORKDIR /tmp/$DEVOPS_DIR_NAME" >> $DOCKERFILE
    echo "RUN python setup.py install" >> $DOCKERFILE
    echo "RUN sed -i '/git.*/d' $REQ_FILE" >> $DOCKERFILE
    echo "RUN pip install -r $REQ_FILE" >> $DOCKERFILE
    echo "WORKDIR /tmp" >> $DOCKERFILE
    echo "RUN rm -rf $DEVOPS_DIR_NAME" >> $DOCKERFILE


    docker build --force-rm=true -t $NAILGUN_IMAGE_NAME $SCRIPTS_TMP_FOLDER_FOR_DOCKER
    docker save $NAILGUN_IMAGE_NAME > $NAILGUIN_TAR_FILE
}

function remove_dirs() {
    sudo rm -rf "$NAILGUN_CONTAINER_TMP_FOLDER"
    sudo rm -rf "$NAILGUN_CONTENT_TMP_FOLDER"
    sudo rm -rf "$WHOLE_ISO_TMP"
    sudo rm -rf "$SCRIPTS_TMP_FOLDER_FOR_DOCKER"
    sudo rm -rf "$DOCKER_IMAGES_FOLDER"
    sudo rm -rf "$ISO_MNT_FOLDER"
    sudo rm -rf "$CERT_PATH"
    sudo rm -rf "$TEST_PATH"
    sudo rm -rf "$CERT_PATH_GIT"
    sudo rm -rf "$TEST_PATH_GIT"
}

function prepare_dirs() {
    mkdir -p "$TMP_FOLDER"
    mkdir -p "$NAILGUN_CONTAINER_TMP_FOLDER"
    mkdir -p "$NAILGUN_CONTENT_TMP_FOLDER"
    mkdir -p "$WHOLE_ISO_TMP"
    mkdir -p "$SCRIPTS_TMP_FOLDER_FOR_DOCKER"
    mkdir -p "$DOCKER_IMAGES_FOLDER"
    mkdir -p "$ISO_MNT_FOLDER"
}

function remake_iso() {
    cp -r "$ISO_MNT_FOLDER/." "$WHOLE_ISO_TMP"

    sudo rm -rf "$WHOLE_ISO_TMP/rr_moved"

    LOCAL_IMAGES_ARCHIVE="$WHOLE_ISO_TMP/docker/images/fuel-images.tar.lrz"
    sudo rm -f "$LOCAL_IMAGES_ARCHIVE"
    sudo cp "$NEW_DOCKER_IMAGE" "$LOCAL_IMAGES_ARCHIVE"

    sudo mkisofs -r -V "FUEL_CERT_ISO" -J -T -R -b isolinux/isolinux.bin \
                -no-emul-boot -boot-load-size 4 -boot-info-table \
                -o "$RESULT_ISO" "$WHOLE_ISO_TMP"
}

function main() {
    remove_dirs
    remote_old_nailgun_container
    prepare_dirs
    test_environment
    checkout_code

    # mount iso image
    sudo mount -o loop "$ISO_PATH" "$ISO_MNT_FOLDER"

    # extract_containers_images
    # lrzuntar creates temporary file in current folder
    pushd $TMP_FOLDER
    lrzuntar -O "$DOCKER_IMAGES_FOLDER" "$DOCKER_IMAGE" 
    popd

    using_docker_file
    repack_containers_archive
    remake_iso

    # umount iso image
    sudo umount "$ISO_MNT_FOLDER"

    remove_dirs
    echo "Results are stored in $RESULT_ISO"
}

main



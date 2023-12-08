#!/bin/bash

# WARNING!  This file is auto updated from the node manager.  Any changes will
# be lost when the client disconnects and reconnects.
#
# Grab the specified git source tree or rpm (when functionality added),
# build it and run the specified plugin with the supplied uri and password

if [ "$#" -ne 5 ]; then
    echo "syntax: ci_unit_test.sh [git|rpm] path/repo ver/branch <array uri> <array password>"
    exit 1
fi

what=$1
loc=$2
ver=$3
uri=$4
pw=$5

# The working directory for this script
base_dir="/tmp/lsm_ci/src/$RANDOM"
src_dir="${base_dir}/libstoragemgmt"
build_dir="${base_dir}/build"

# The directory the functions in the source tree are going to use
run_dir="/tmp/lsm_ci/run"
run_dir_rand="${run_dir}/$RANDOM"

function cleanup
{
    if [ -d "${base_dir}" ]; then
        echo "Deleting ${base_dir}"
        rm -rf  "${base_dir}"
    fi

    if [ -d  "${run_dir_rand}" ]; then
        echo "Deleting ${run_dir_rand}"
        rm -rf  "${run_dir_rand}"
    fi
}

function good
{
    # test_include.sh has this function, but we need to run a number of
    # commands before we can fetch the source to utilize it
    echo "executing: $*"
    eval "$@"
    local ec=$?
    if [ ${ec} -ne 0 ]; then
        echo "Fail exit[${ec}]: $1"
        exit 1
    fi
}

function run_test
{
    good ./autogen.sh

    if [ "CHK$(rpm -E %{?el7})" != "CHK" ];then
        echo "EL7 does not have all dependencies in python3"
        good ./configure "$1" --with-python2
    else
        good ./configure "$1"
    fi

    good make

    # Source in the helpers functions that are included with the source tree
    good source "${src_dir}/test/test_include.sh"

    # Install, start lsmd and run the plugin unit test and clean-up when done
    lsm_test_base_install "${run_dir_rand}" "${src_dir}" "${src_dir}" \
        "${LSM_TEST_INSTALL_ALL_PLUGINS}"

    lsm_test_lsmd_start "${LSM_TEST_WITHOUT_MEM_CHECK}"

    # This will test everything
    lsm_test_plugin_test_run "${uri}"  "${pw}"

    lsm_test_cleanup
}

# When we exit we are going to clean up what we created so we don't fill
# the FS up, comment this out if we need the files around to debug
trap cleanup EXIT

# Make the needed directories, but don't make the destination directory for
# argument 1 for lsm_test_base_install as it wants to create it
good mkdir -p "${base_dir}"
good mkdir -p "${build_dir}"
good mkdir -p "${run_dir}"

# Start in a consistent spot
good cd "${base_dir}"

# Fetch the code or rpm, or make sure rpm version is installed
if [ "${what}" = "git" ] ; then
    good git clone "${loc}" --branch "${ver}"
else
    echo "Testing with RPMs not completed yet!"
    exit 1
fi

good cd "${src_dir}"

# Do basic test.
run_test ""

exit 0


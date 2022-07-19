#!/bin/bash
#
# Create a RESim Ghidra plugins release.
#
#
release_dir=$HOME/resimGhidraRelease/RESimGhidraPlugins
if [[ ! -d $release_dir ]]; then
    echo "No $release_dir directory found"
    exit 
fi
if [[ -z "$1" ]]; then
    tag=$(git tag | tail -n 1)
    echo "Missing tag, most recent is "$tag" .  Pick the next revision."
    exit
fi
if [[ -z "$gitpat" ]]; then
    echo "gitpat is not defined.  Source the release/gitpat file"
    exit
fi
if [[ -z "$SSH_AGENT_PID" ]]; then
    echo "No ssh-agent running.  Source ~/agent.sh"
    exit
fi
if [[ ! -d release ]]; then
    echo "Run it from the parent directory, e.g., ./release/mkrelease.sh"
    exit 
fi
git pull || exit
git push --set-upstream origin master || exit

new_tag=$1
here=`pwd`

mkdir -p $release_dir/lib
mkdir -p release/artifacts
here=`pwd`
cp lib/*.jar $release_dir/lib
cp build/libs/RESimGhidraPlugins.jar $release_dir/lib
cp extension.properties $release_dir/

cd $release_dir
cd ..
tar czf $here/release/artifacts/RESimGhidraPlugins.tar RESimGhidraPlugins
echo "Now generate release"
cd $here
git tag $new_tag
git push --set-upstream origin master
git push --tags

github-release release --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag
echo "wait for github"
while [ -z "$(github-release info --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag | grep releases:)" ]; do
    echo "release not yet created, sleep 2"
    sleep 2
done
echo "Upload RESim plugins"
github-release upload --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag --name RESimGhidraPlugins.tar --file release/artifacts/RESimGhidraPlugins.tar
#git fetch --tags

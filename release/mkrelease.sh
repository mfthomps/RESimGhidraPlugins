#!/bin/bash
#
# Create a RESim Ghidra plugins release.
# Assumes you've exported the jar file using the GhidraDev plugin
# and the result is in ~/eclipse-workspace/RESimPlugin/dist
#
#
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
git checkout master || exit
dist_dir=~/eclipse-workspace/RESimPlugin/dist
latest=$(ls -t $dist_dir | head -n 1)
echo "Will release latest: $latest"
full=$dist_dir/$latest
rm -fr artifacts
mkdir -p artifacts
cp $full artifacts/

new_tag=$1
here=`pwd`

git tag $new_tag
#git push --set-upstream origin master
git push --tags

github-release release --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag
echo "wait for github"
while [ -z "$(github-release info --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag | grep releases:)" ]; do
    echo "release not yet created, sleep 2"
    sleep 2
done
echo "Upload RESim plugins"
github-release upload --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag --name $latest --file release/artifacts/$latest
#git fetch --tags

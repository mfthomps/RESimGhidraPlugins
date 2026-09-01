#!/bin/bash
#
# Create a RESim Ghidra plugins release.
# Assumes you've exported the jar file using the GhidraDev plugin
# and the result is in ~/neweclipse2/RESimPluginY/dist
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
dist_dir=~/neweclipse2/RESimPluginY/dist
latest=$(ls -t $dist_dir | head -n 1)
echo "Will release latest: $latest"
full=$dist_dir/$latest
rm -fr release/artifacts
mkdir -p release/artifacts
cp $full release/artifacts/

new_tag=$1
here=`pwd`

version_file=$dist_dir/../src/main/resources/data/version.txt
version_string=$(cat $version_file)
echo "new_tag is $new_tag version string is $version_string"
if [[ "$new_tag" != "$version_string" ]]; then
    echo "versions do not match"
    exit
else
    echo "versions ok"
fi
git tag $new_tag || exit
#git push --set-upstream origin master
git push --tags

echo "github-release release --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag"
github-release release --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag
echo "wait for github"
while [ -z "$(github-release info --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag | grep releases:)" ]; do
    echo "release not yet created, sleep 2"
    sleep 2
done
echo "Upload RESim plugins"
github-release upload --security-token $gitpat --user mfthomps --repo RESimGhidraPlugins --tag $new_tag --name $latest --file release/artifacts/$latest
#git fetch --tags

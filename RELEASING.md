# Prepare
- add new O/S versions in pkg/rules/packages-to-build.yml if needed
- update Changelog.md with the release date, version X.Y.Z[-NNN] and release summary

# Make a release branch and test packaging
- git checkout -b release-vX.Y.Z[-xxx]
- switch to the MRSV listed in Cargo.toml.
- cargo update
- bump application version in Cargo.toml to X.Y.Z[-xxx]
- cargo check (to bump the application version in Cargo.lock)
- pushd doc/manual
- make man
- popd
- git add Cargo.toml Cargo.lock Changelog.md pkg/rules/packages-to-build.yml doc/manual/build/man/*.*
- git commit -m 'Prepare for release'
- git push
- in GH UI invoke the packaging workflow on the release branch
- make a PR for the branch and mention the workflow run URL in the descrption
- review the PR and ensure the workflow succeeds

# Merge and release
- merge the release branch to main
- git tag -a -m "Release vX.Y.Z[-xxx]" vX.Y.Z[-xxx]
- git push --tags
- create a GH release for the tag
- publish binary (DEB, RPM) packages from GH actions packaging run via packaging VM

# Prepare for development
- git checkout -b prep-for-dev
- bump application version in Cargo.toml to next minor version with suffix `-dev`
- cargo check (to also bump the application version in Cargo.lock)
- git add Cargo.toml Cargo.lock
- git commit
- git push

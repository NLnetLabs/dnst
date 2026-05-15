# As we're building on a glibc system, the binary depends on glibc symbols and
# libraries. Therefore, we need to use a glibc base image (not apline).
ARG BASE_IMG=debian:13-slim

FROM ${BASE_IMG}

# Install required runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends tini
# apt cache get's cleaned automatically

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/dnst /usr/bin/

# Set the working directory so that users can easily mount a host filesystem
# path where the dnst commands can read from and write to, e.g. via docker
# run -v /tmp/:/data.
WORKDIR /data

# Use Tini to ensure that our application responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
ENTRYPOINT ["/usr/bin/tini", "--", "dnst"]

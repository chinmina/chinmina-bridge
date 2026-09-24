# Runtime image for the chinmina-bridge workers in the local integration stack.
#
# The binary itself is not baked in: the repo is bind-mounted at /src and the
# worker runs ./dist/chinmina-bridge from there, so a rebuild on the host is
# picked up without rebuilding this image.
#
# The worker health check runs `chinmina-bridge healthcheck` from the same
# mount, so the image needs no HTTP probe of its own.
FROM cgr.dev/chainguard/busybox:latest

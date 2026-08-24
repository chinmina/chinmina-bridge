# Runtime image for the chinmina-bridge workers in the local integration stack.
#
# The binary itself is not baked in: the repo is bind-mounted at /src and the
# worker runs ./dist/chinmina-bridge from there, so a rebuild on the host is
# picked up without rebuilding this image.
FROM cgr.dev/chainguard/busybox:latest

# statically linked, no-dependency HTTP probe (~70KB)
COPY --from=tarampampam/microcheck:1 /bin/httpcheck /usr/local/bin/httpcheck

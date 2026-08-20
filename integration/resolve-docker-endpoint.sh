#!/bin/bash
#
# Resolve how traefik reaches the Docker API from inside its container, for the
# integration docker-compose stack.
#
# Usage: resolve-docker-endpoint.sh [ENDPOINT]
#
# Prints two space-separated fields for the caller to export: the host path to
# bind at /var/run/docker.sock (DOCKER_SOCKET), and the endpoint traefik's
# docker provider dials (DOCKER_ENDPOINT). How it gets there depends on how the
# local docker CLI talks to the daemon:
#
#   unix://PATH   bind the socket in. Only an admin install puts it at the
#                 default /var/run/docker.sock; OrbStack, Rancher Desktop and
#                 colima each use a path under $HOME.
#   tcp://LOCAL   a port on this host is not reachable as "localhost" from
#                 inside a container, so dial host.docker.internal instead.
#   tcp://REMOTE  reachable as-is.
#
# ENDPOINT overrides discovery, for testing a path the local docker setup does
# not use: `./resolve-docker-endpoint.sh tcp://localhost:2375`.

set -euo pipefail

# Port assumed when a tcp endpoint omits one.
readonly DEFAULT_DOCKER_PORT=2375

# Hostname that resolves to this host from inside a container.
readonly CONTAINER_HOST_ALIAS='host.docker.internal'

# Print a message to STDERR.
err() {
  echo "$*" >&2
}

# Echo the docker endpoint URL to use, in the precedence the docker CLI itself
# applies: an explicit argument, then DOCKER_HOST, then the active context.
resolve_endpoint() {
  local explicit="${1:-}"

  if [[ -n "${explicit}" ]]; then
    printf '%s\n' "${explicit}"
    return 0
  fi

  if [[ -n "${DOCKER_HOST:-}" ]]; then
    printf '%s\n' "${DOCKER_HOST}"
    return 0
  fi

  docker context ls --format json |
    jq -r 'select(.Current == true) | .DockerEndpoint'
}

# Echo the host and port of a URL, space separated, defaulting the port when
# the URL omits one. Handles bracketed IPv6 literals.
split_hostport() {
  local hostport="${1#*://}" host port

  case "${hostport}" in
    \[*\]*) # bracketed IPv6 literal
      host="${hostport%%\]*}"
      host="${host#\[}"
      port="${hostport##*\]}"
      port="${port#:}"
      ;;
    *:*)
      host="${hostport%%:*}"
      port="${hostport##*:}"
      ;;
    *)
      host="${hostport}"
      port=''
      ;;
  esac

  printf '%s %s\n' "${host}" "${port:-${DEFAULT_DOCKER_PORT}}"
}

# Entry point. Receives an optional endpoint override as "$1".
main() {
  local endpoint socket provider host port

  endpoint="$(resolve_endpoint "${1:-}")"

  case "${endpoint}" in
    '')
      err "error: no docker endpoint found: is the docker CLI installed?"
      return 1
      ;;

    unix://*)
      # Bound in below, so traefik uses the container's default path.
      socket="${endpoint#unix://}"
      provider='unix:///var/run/docker.sock'

      if [[ ! -S "${socket}" ]]; then
        err "error: '${socket}' is not a socket: is docker running?"
        return 1
      fi
      ;;

    tcp://*|http://*|https://*)
      # No socket to bind: /dev/null keeps the compose mount harmless, as
      # traefik never looks at it in this mode.
      socket='/dev/null'
      read -r host port < <(split_hostport "${endpoint}")

      case "${host}" in
        localhost|127.0.0.1|0.0.0.0|::1)
          # The daemon listens on this host, not in the container's netns.
          provider="tcp://${CONTAINER_HOST_ALIAS}:${port}"
          ;;
        *:*) # bracket IPv6 literals; split_hostport stripped them
          provider="tcp://[${host}]:${port}"
          ;;
        *)
          provider="tcp://${host}:${port}"
          ;;
      esac

      if [[ -n "${DOCKER_TLS_VERIFY:-}" ]]; then
        err "warning: DOCKER_TLS_VERIFY is set, but traefik has no client" \
          "certificates: docker discovery will likely fail"
      fi
      ;;

    *)
      err "error: docker endpoint '${endpoint}' cannot be reached from a" \
        "container: pass a unix socket or a tcp address"
      return 1
      ;;
  esac

  printf '%s %s\n' "${socket}" "${provider}"
}

main "$@"

#!/bin/bash
set -euo pipefail

directory="$(realpath --relative-to=. "$(dirname "${BASH_SOURCE[0]}")")"

function check_path {
    if ! which "${1}" >/dev/null 2>&1; then
        echo -e '\x1b[31m'"${1}"' not found, did you forget to source the venv?\x1b[0m' >&2
        exit 1
    fi
}
check_path enochecker_cli
check_path enochecker_test


args=()
mode=""
checker_connection=(-n router-checker)
service_connection=(-N router)
checker_port=8000
flag_regex="ECSC\{[A-Za-z0-9-_]{32}\}"
extra_args=() # Mostly here to pass enochecker_cli's non-tool-specific options

while [ "$#" -gt 0 ]; do
    case "${1}" in
        load|test|help) mode="${1}";;
        --help|-h)               mode=help;;
        -n|--checker-network)    checker_connection=(-n "${2}"); shift;;
        -a|--checker-address)    checker_connection=(-a "${2}"); shift;;
        -p|--checker-port)       checker_port="${2}"; shift;;
        -N|--service-network)    service_connection=(-N "${2}"); shift;;
        -A|--service-address)    service_connection=(-A "${2}"); shift;;
        -f|--flag-regex)         flag_regex="${2}"; shift;;
        -X|--extra)              extra_args+=("${2}"); shift;;
        --)                      shift; args+=("$@"); break;;
        *)                       args+=("${1}");;
    esac
    shift
done

if [ -z "${mode}" ]; then
    for arg in "${args[@]}"; do
        case arg in
            --) break;;
            -*) ;;
            *)  echo "${arg} is not a valid mode (see '${0} help' for details)" >&2; exit 1;;
        esac
    done
    mode=test
fi

network_args=("${checker_connection[@]}" -p "${checker_port}" "${service_connection[@]}" --flag-regex "${flag_regex}")
case "${mode}" in
    test)
        tool=(enochecker_test "${network_args[@]}" "${extra_args[@]}" "${args[@]}")
        ;;
    load)
        tool=(enochecker_cli "${network_args[@]}" "${extra_args[@]}" sim "${args[@]}")
        ;;
    help)
        echo "${0} {test,load,help} [-n CHECKER_NETWORK|-a CHECKER_ADDRESS] [-p CHECKER_PORT] [-N SERVICE_NETWORK|-A SERVICE_ADDRESS] [--] [arguments...]"
        exit 0
        ;;
    *) echo "\x1b[31mUnknown mode ${1}, try '${0} help'\x1b[0m" >&2; exit 1;;
esac

set -x
exec "${tool[@]}"

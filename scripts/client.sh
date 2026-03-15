#!/usr/bin/env bash
set -euo pipefail

# Talos Certificate Issuance Client
# Usage: bash client.sh <server-hostname> [--port PORT] [--out-dir DIR]

readonly VERSION="0.1.2"
readonly DEFAULT_PORT="18443"
readonly DEFAULT_OUT_DIR="."

main() {
    local server=""
    local port="${DEFAULT_PORT}"
    local out_dir="${DEFAULT_OUT_DIR}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)   port="$2"; shift 2 ;;
            --out-dir) out_dir="$2"; shift 2 ;;
            --help|-h) usage; exit 0 ;;
            -*)        echo "Error: Unknown option $1" >&2; usage; exit 1 ;;
            *)         server="$1"; shift ;;
        esac
    done

    if [[ -z "${server}" ]]; then
        echo "Error: Server hostname is required." >&2
        usage
        exit 1
    fi

    # Check prerequisites
    command -v curl >/dev/null 2>&1 || { echo "Error: curl is required." >&2; exit 1; }
    command -v tar  >/dev/null 2>&1 || { echo "Error: tar is required." >&2; exit 1; }
    command -v klist >/dev/null 2>&1 || { echo "Error: klist (Kerberos) is required." >&2; exit 1; }

    # Verify Kerberos ticket
    if ! klist -s 2>/dev/null; then
        echo "Error: No valid Kerberos ticket found. Run 'kinit <principal>' first." >&2
        exit 1
    fi

    local principal
    principal=$(klist 2>/dev/null | grep "Default principal:" | awk '{print $3}')
    echo "Using identity: ${principal}"

    # Create output directory if needed
    mkdir -p "${out_dir}"

    # Request certificate bundle
    echo "Connecting to ${server}:${port}..."
    local tmpfile
    tmpfile=$(mktemp)
    trap 'rm -f "${tmpfile}"' EXIT

    local http_code
    http_code=$(curl -s -o "${tmpfile}" -w "%{http_code}" \
        --negotiate -u : \
        "https://${server}:${port}/v1/issue")

    case "${http_code}" in
        200)
            echo "Issuing certificate... Complete"
            ;;
        401)
            echo "Error: Authentication failed. Your Kerberos ticket may be invalid or expired." >&2
            exit 1
            ;;
        403)
            echo "Error: 403 Forbidden — principal is not authorized for certificate issuance." >&2
            exit 1
            ;;
        *)
            echo "Error: Server returned HTTP ${http_code}." >&2
            exit 1
            ;;
    esac

    # Extract bundle
    echo "Downloading... Complete"
    tar -xzf "${tmpfile}" -C "${out_dir}"

    # Set permissions
    find "${out_dir}" -name '*.key' -exec chmod 0600 {} \;

    # List extracted files
    echo ""
    echo "Files downloaded:"
    tar -tzf "${tmpfile}" | while read -r f; do
        echo "  ${f}"
    done
}

usage() {
    echo "Usage: client.sh <server-hostname> [--port PORT] [--out-dir DIR]"
    echo ""
    echo "Options:"
    echo "  --port PORT     Issuance server port (default: ${DEFAULT_PORT})"
    echo "  --out-dir DIR   Output directory (default: current directory)"
    echo "  --help, -h      Show this help message"
}

main "$@"

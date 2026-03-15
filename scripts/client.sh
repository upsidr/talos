#!/usr/bin/env bash
set -euo pipefail

# Talos Certificate Issuance Client
# Usage: bash client.sh <server-hostname> [--port PORT] [--out-dir DIR] [--resolve IP] [--insecure]

readonly VERSION="0.1.2"
readonly DEFAULT_PORT="18443"
readonly DEFAULT_OUT_DIR="."
tmpfile=""

main() {
    local server=""
    local port="${DEFAULT_PORT}"
    local out_dir="${DEFAULT_OUT_DIR}"
    local resolve_ip=""
    local insecure=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)      port="$2"; shift 2 ;;
            --out-dir)   out_dir="$2"; shift 2 ;;
            --resolve)   resolve_ip="$2"; shift 2 ;;
            --insecure)  insecure=true; shift ;;
            --help|-h)   usage; exit 0 ;;
            -*)          echo "Error: Unknown option $1" >&2; usage; exit 1 ;;
            *)           server="$1"; shift ;;
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

    # Extract principal — handles both MIT ("Default principal:") and Heimdal ("Principal:") klist output
    local principal
    principal=$(klist 2>/dev/null | awk '/[Pp]rincipal:/ {print $NF; exit}')
    if [[ -z "${principal}" ]]; then
        echo "Error: Could not determine Kerberos principal from klist output." >&2
        echo "  Hint: Run 'klist' manually to verify your ticket." >&2
        exit 1
    fi
    echo "Using identity: ${principal}"

    # Create output directory if needed
    mkdir -p "${out_dir}"

    # Request certificate bundle
    echo "Connecting to ${server}:${port}..."
    tmpfile=$(mktemp)
    trap 'rm -f "${tmpfile}"' EXIT

    local curl_args=(
        --silent --show-error
        --output "${tmpfile}"
        --write-out "%{http_code}"
        --negotiate -u :
        -X POST
    )

    if [[ -n "${resolve_ip}" ]]; then
        curl_args+=(--resolve "${server}:${port}:${resolve_ip}")
    fi

    if [[ "${insecure}" == true ]]; then
        curl_args+=(--insecure)
    fi

    local http_code
    local curl_exit=0
    http_code=$(curl "${curl_args[@]}" \
        "https://${server}:${port}/v1/issue") || curl_exit=$?

    if [[ ${curl_exit} -ne 0 ]]; then
        echo "" >&2
        echo "Error: curl failed with exit code ${curl_exit}." >&2
        case ${curl_exit} in
            6)  echo "  Could not resolve hostname '${server}'." >&2
                if [[ -z "${resolve_ip}" ]]; then
                    echo "  Hint: Use --resolve <IP> to map the hostname to an IP address." >&2
                fi
                ;;
            7)  echo "  Could not connect to ${server}:${port}." >&2
                echo "  Hint: Check that the issuance server is running and the port is correct." >&2
                ;;
            35) echo "  TLS handshake failed." >&2
                echo "  Hint: If the server uses a self-signed certificate, try --insecure." >&2
                ;;
            51) echo "  TLS certificate verification failed." >&2
                echo "  Hint: If the server uses a self-signed certificate, try --insecure." >&2
                ;;
            60) echo "  TLS certificate verification failed (untrusted CA)." >&2
                echo "  Hint: If the server uses a self-signed certificate, try --insecure." >&2
                ;;
            *)  echo "  See https://curl.se/libcurl/c/libcurl-errors.html for details." >&2
                ;;
        esac
        exit 1
    fi

    case "${http_code}" in
        200)
            ;;
        401)
            echo "Error: Authentication failed (HTTP 401)." >&2
            echo "  Your Kerberos ticket may be invalid or expired." >&2
            echo "  Hint: Run 'klist' to check your ticket, or 'kinit' to obtain a new one." >&2
            exit 1
            ;;
        403)
            echo "Error: Forbidden (HTTP 403)." >&2
            echo "  Principal '${principal}' is not authorized for certificate issuance." >&2
            echo "  Hint: Check allowed_principals / allowed_realms in the server config." >&2
            exit 1
            ;;
        405)
            echo "Error: Method Not Allowed (HTTP 405)." >&2
            echo "  The server rejected the request method. This is likely a client bug." >&2
            exit 1
            ;;
        *)
            echo "Error: Server returned HTTP ${http_code}." >&2
            # Show response body if it's small text (likely an error message)
            local body_size
            body_size=$(wc -c < "${tmpfile}" | tr -d ' ')
            if [[ ${body_size} -gt 0 && ${body_size} -lt 1024 ]]; then
                echo "  Response: $(cat "${tmpfile}")" >&2
            fi
            exit 1
            ;;
    esac

    # Extract bundle
    if ! tar -xzf "${tmpfile}" -C "${out_dir}" 2>/dev/null; then
        echo "Error: Failed to extract certificate bundle." >&2
        echo "  The server response may not be a valid tar.gz archive." >&2
        exit 1
    fi

    # Set permissions
    find "${out_dir}" -name '*.key' -exec chmod 0600 {} \;

    # List extracted files
    echo ""
    echo "Certificate issued successfully."
    echo "Files:"
    tar -tzf "${tmpfile}" | while read -r f; do
        echo "  ${out_dir}/${f}"
    done
}

usage() {
    cat <<EOF
Talos Certificate Issuance Client v${VERSION}

Usage: client.sh <server-hostname> [options]

Options:
  --port PORT       Issuance server port (default: ${DEFAULT_PORT})
  --out-dir DIR     Output directory (default: current directory)
  --resolve IP      Resolve server hostname to this IP address (useful when
                    DNS cannot resolve the server hostname)
  --insecure        Skip TLS certificate verification (for self-signed certs)
  --help, -h        Show this help message

Examples:
  # Basic usage
  client.sh talos-server.example.com

  # With DNS override and self-signed cert
  client.sh talos-server.example.com --resolve 10.0.0.5 --insecure

  # Save certs to a specific directory
  client.sh talos-server.example.com --out-dir ./certs
EOF
}

main "$@"

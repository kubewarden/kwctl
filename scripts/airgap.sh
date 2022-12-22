#!/usr/bin/env bash
set -eEuo pipefail

# ==================================================================================================
# TODO:
# Questions:
# - should I keep --registry for kubewarden-defaults chart (policyserver)?
# - should I enable recommended policies by default?
#
# Review (Victor): https://github.com/kubewarden/kwctl/pull/375#discussion_r1048740479
# current approach doesn't use the GH release files kubewarden-crds-1.2.3_kubewarden-defaults-1.2.8_kubewarden-controller-1.2.8_policylist.txt
# - it does
# canonical locations of artifacts
# - please explain (helm charts vs release?)
#
# TODO:
# fix https://docs.kubewarden.io/operator-manual/airgap/requirements
# blogpost - https://github.com/kubewarden/kubewarden.io/pull/153
# fix documentation - https://github.com/kubewarden/docs/pull/150
# ==================================================================================================


# Defaults
IMAGES_TAR="kubewarden-images.tar"
POLICIES_TAR="kubewarden-policies.tar.gz"

PROG=airgap
USAGE="\
Usage:  $PROG command [--parameters]

  $PROG list [--cert-manager]
  $PROG pull -l file.json [--dry]
  $PROG push -l file.json -r registry[:port] [--insecure] [--dry]
  $PROG install -l file.json -r registry[:port] [--insecure] [--dry]

Parameters:
  -l|--list       Json file with list of required dependencies
  -r|--registry   Private registry where artifacts are pushed. Helm charts are configured for this registry
  --dry           Do not perform actions, only print commands that would be executed
  --cert-manager  Include cert-manager dependencies in the generated list
  --insecure      For pull command skip kwctl certificate verification (an alternative to sources.yaml file)
                  For install disable policyServer verification of registry

Commands:
  list     Generate json list of dependencies. You can redirect it to a file
  pull     Pull components from list to current directory
  push     Push components in list from current directory to local registry
  install  Install helm charts configured with local registry

Requirements: (https://docs.kubewarden.io/operator-manual/airgap/requirements)
  - jq, kwctl, helm, docker
  - kubewarden helm repository

Examples:
  Generate list of dependencies required by airgap. Save in file for other commands:
    $PROG list --cert-manager | tee file.json

  Pull images and policies and save them to archives in current directory:
    $PROG pull --list file.json

  Push images and policies from created archives to local registry. Run in DRY mode:
    $PROG push --list file.json --registry=localhost:5123 --dry

  Helm install charts from local files. Registry is used for recommendedPolicies setup:
    $PROG install --list file.json --registry 172.18.0.4:5000"

# ==================================================================================================
# Helper Functions & traps

shopt -s expand_aliases
alias curl="curl -# -L"

# Print error message (or usage) and exit
function error { echo -e "${1:-$USAGE}" >&2; exit 1; }

# Print green colored message
function step { printf -- "\e[32m# %s\e[0m\n" "${*}"; }

# shellcheck disable=SC2015
# Print command that would be executed in DRY mode
function dry { [ -v DRY ] && echo "- $*" || "$@"; }

# Transform lines to json array key -> [lines]
function to_json { cat < /dev/stdin | jq -s -c -R --arg key "$1" '{ ($key): split("\n") | map(select(length > 0)) }'; }

# Get archive location from chart line: https://charts.kubewarden.io/kubewarden-crds:1.2.3 -> kubewarden-crds-1.2.3.tgz
# function chart_file { jq -er --arg chart "$1" '$chart +"-"+ (.charts[] | select(contains($chart)) | split(":")[-1]) +".tgz"' <<< "$LIST"; }
function chart_file { printf -- '%s\n' "${charts[@]##*/}" | grep "$1" | tr ':' '-' | sed 's/$/.tgz/'; }

# Print line with error
trap 'echo "Error on ${BASH_SOURCE}:${LINENO} $(sed -n "${LINENO} s/^\s*//p" ${BASH_SOURCE})"' ERR

# ==================================================================================================
# Generate json from all components required by airgap

function command_list {
   local tag url urls images policies charts

   tag=$(helm search repo kubewarden/kubewarden-defaults -o json | jq -er 'first.version')
   urls=$(curl "https://api.github.com/repos/kubewarden/helm-charts/releases/tags/kubewarden-defaults-$tag" | jq -er '.assets[].browser_download_url')

   # images
   url=$(grep 'images.txt$' <<< "$urls")
   images=$(curl "$url" | to_json 'images')
   if [ -v CERTMAN ]; then
      local cimages
      cimages=$(helm template --repo https://charts.jetstack.io cert-manager | awk '$1 ~ /image:/ {print $2}' | tr -d '"' | to_json 'images')
      images=$(echo "$images" | jq -ec --argjson c "$cimages" '.images += $c.images')
   fi

   # policies
   url=$(grep 'policylist.txt$' <<< "$urls")
   policies=$(curl "$url" | to_json 'policies')

   # charts
   url=$(helm repo list | grep ^kubewarden | awk '{print $2}')
   charts=$(helm search repo kubewarden -o json | jq -ec --arg repo "$url/" '{"charts": map($repo + (.name|split("/")[1]) + ":" + .version)}')
   if [ -v CERTMAN ]; then
      charts=$(echo "$charts" | jq -ec '.charts += ["https://charts.jetstack.io/cert-manager:v1.10.1"]')
   fi

   echo "${images:-}" "${policies:-}" "${charts:-}" | jq -es 'add'
}

# ==================================================================================================
# Functions for pulling images & policies & charts to local archives

function pull_images {
   [ -e "$IMAGES_TAR" ] && { echo "File $IMAGES_TAR exists, skipping."; return; }

   for line in "${images[@]}"; do
      dry docker pull -q "$line"
   done
   [ -v DRY ] || echo "Create $IMAGES_TAR from pulled images"
   dry docker save --output "$IMAGES_TAR" "${images[@]}"
}

function pull_policies {
   [ -e "$POLICIES_TAR" ] && { echo "File $POLICIES_TAR exists, skipping."; return; }

   for line in "${policies[@]}"; do
      [ -v DRY ] || echo "$line"
      dry kwctl pull "$line"
   done
   [ -v DRY ] || echo "Create $POLICIES_TAR from pulled policies"
   dry kwctl save --output "$POLICIES_TAR" "${policies[@]}"
}

function pull_charts {
   local repo chart tag

   for line in "${charts[@]}"; do
      repo=${line%/*}
      chart=$(basename "$line" | cut -d: -f1)
      tag=${line##*:}
      [ -e "$chart-$tag.tgz" ] && { echo "File $chart-$tag.tgz exists, skipping."; continue; }
      [ -v DRY ] || echo "$line"
      dry helm pull --repo "$repo" "$chart" --version="$tag"
   done
}

# Call respective functions if array is not empty
function command_pull {
   [ -n "${images:-}" ]   && { step "Pull images"; pull_images; }
   [ -n "${policies:-}" ] && { step "Pull policies"; pull_policies; }
   [ -n "${charts:-}" ]   && { step "Pull charts"; pull_charts; }
   return 0
}

# ==================================================================================================
# Functions for pushing images & policies into $REGISTRY

function push_images {
   [ -e "$IMAGES_TAR" ] || { echo "File $IMAGES_TAR does not exist."; return; }

   dry docker load --input "$IMAGES_TAR"
   # tar -xOf $IMAGES_TAR manifest.json | jq -re '.[].RepoTags[]'
   for img in "${images[@]}"; do
      target=$REGISTRY/${img#*/}
      dry docker tag "$img" "$target"
      dry docker push -q "$target"
   done
}

function push_policies {
   [ -e "$POLICIES_TAR" ] || { echo "File $POLICIES_TAR does not exist."; return; }

   [ -v DRY ] || echo "Loading archive: $POLICIES_TAR"
   dry kwctl load --input "$POLICIES_TAR"
   # tar -tf $POLICIES_TAR | sed 's#/#://#'
   for pol in "${policies[@]}"; do
      target=$(sed -E "s#.*://[^/]+#registry://$REGISTRY#" <<< "$pol")
      dry kwctl push "$pol" "$target" ${INSECURE:+--sources-path <(echo "insecure_sources: [$REGISTRY]")}
   done
}

function command_push {
   [ -n "${images:-}" ]   && { step "Push images"; push_images; }
   [ -n "${policies:-}" ] && { step "Push policies"; push_policies; }
   return 0
}

# ==================================================================================================
# Install charts

function command_install {
   # Install cert-manager only if it's in the list
   if jq -er '.charts | any(contains("cert-manager"))' <<< "$LIST" > /dev/null; then
      step 'Install cert-manager'
      dry helm install cert-manager "$(chart_file cert-manager)" -n cert-manager --create-namespace \
         --set installCRDs=true \
         --set "image.repository=$REGISTRY/jetstack/cert-manager-controller" \
         --set "webhook.image.repository=$REGISTRY/jetstack/cert-manager-webhook" \
         --set "cainjector.image.repository=$REGISTRY/jetstack/cert-manager-cainjector" \
         --set "startupapicheck.image.repository=$REGISTRY/jetstack/cert-manager-ctl"
   fi

   step 'Install kubewarden-crds'
   dry helm install kubewarden-crds "$(chart_file kubewarden-crds)" --create-namespace -n kubewarden

   step 'Install kubewarden-controller'
   dry helm install kubewarden-controller "$(chart_file kubewarden-controller)" -n kubewarden --wait \
      --set "common.cattle.systemDefaultRegistry=$REGISTRY"

   step 'Install kubewarden-defaults'
   dry helm install kubewarden-defaults "$(chart_file kubewarden-defaults)" -n kubewarden \
      --set "common.cattle.systemDefaultRegistry=$REGISTRY" \
      --set recommendedPolicies.enabled=True \
      ${INSECURE:+--set policyServer.insecureSources[0]=$REGISTRY}
}

# ==================================================================================================
# Parse & check parameters and execute

# Check requirements
which jq kwctl helm docker > /dev/null || error "Missing one of requirements"

[ $# -eq 0 ] && error

ACTION="$1"; shift
while [[ $# -gt 0 ]]; do
   case $1 in
   -d|--dry)           DRY=1; shift;;
   -l|--list)          LIST=$(jq -c '.' "$2" || error "Invalid JSON: $2"); shift 2;;
   -r|--registry)      REGISTRY="$2"; shift 2;;
   -c|--cert-manager)  CERTMAN=1; shift;;
   -k|--insecure)      INSECURE=1; shift;;
   -h|--help) error;;
   *) echo "Invalid parameter: $1"; error;;
   esac
done
set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

# Check parameters
[[ "$ACTION" == "list" ]] && { helm repo list | grep ^kubewarden > /dev/null || error "Missing kubewarden repo"; }
[[ "$ACTION" =~ ^(push|install)$ && ! -v REGISTRY ]] && error "Required parameter is missing: --registry"
[[ "$ACTION" =~ ^(pull|push)$ && ! -v LIST ]] && error "Required parameter is missing: --list"
#[[ -v REGISTRY && ! -v DRY && ! $(curl -o /dev/null -s --head --fail "$REGISTRY") ]] && error "Registry $REGISTRY is not reachable"

# Parse json into arrays
if [ -v LIST ]; then
   mapfile -t images < <(jq -r '.images[]?' <<< "$LIST")
   mapfile -t policies < <(jq -r '.policies[]?' <<< "$LIST")
   mapfile -t charts < <(jq -r '.charts[]?' <<< "$LIST")
fi

# Execute
case $ACTION in
   list) command_list;;
   pull) command_pull;;
   push) command_push;;
   install) command_install;;
   *) echo "Unknown command: $*"; error;;
esac

exit 0

use anyhow::Result;
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::{fetch_policy, sources::Sources, PullDestination};

use std::path::PathBuf;

pub(crate) async fn pull(
    uri: &str,
    docker_config: Option<DockerConfig>,
    sources: Option<Sources>,
    destination: PullDestination,
) -> Result<PathBuf> {
    let uri = add_latest_if_tag_not_present(uri);
    fetch_policy(&uri, destination, docker_config, sources.as_ref()).await
}

fn add_latest_if_tag_not_present(uri: &str) -> String {
    if is_registry_and_does_not_contain_tag(uri) {
        let latest_tag = "latest";
        [uri, latest_tag].join(":")
    } else {
        uri.to_string()
    }
}

fn is_registry_and_does_not_contain_tag(uri: &str) -> bool {
    let v: Vec<&str> = uri.split(':').collect();
    v[0] == "registry" && v.len() == 2
}

#[cfg(test)]
mod tests {
    use crate::pull::add_latest_if_tag_not_present;

    #[test]
    fn test_latest_tag_is_added_if_tag_not_present() {
        let uri = "registry://ghcr.io/kubewarden/policies/psp-capabilities";
        let uri_expected = "registry://ghcr.io/kubewarden/policies/psp-capabilities:latest";
        assert_eq!(uri_expected, add_latest_if_tag_not_present(uri))
    }

    #[test]
    fn test_latest_tag_is_not_added_if_tag_present() {
        let uri = "registry://ghcr.io/kubewarden/policies/psp-capabilities:v1";
        assert_eq!(uri, add_latest_if_tag_not_present(uri))
    }

    #[test]
    fn test_latest_tag_is_not_added_if_not_registry() {
        let uri = "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.9/policy.wasm";
        assert_eq!(uri, add_latest_if_tag_not_present(uri))
    }

    #[test]
    fn test_latest_tag_empty_uri() {
        let uri = "";
        assert_eq!(uri, add_latest_if_tag_not_present(uri))
    }
}

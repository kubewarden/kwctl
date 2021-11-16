use anyhow::{anyhow, Result};
use policy_fetcher::registry::config::DockerConfig;
use policy_fetcher::sources::Sources;
use policy_fetcher::verify::Verifier;
use std::{collections::HashMap, fs};
use tracing::info;

pub(crate) type VerificationAnnotations = HashMap<String, String>;

pub(crate) async fn verify(
    url: &str,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    annotations: Option<&VerificationAnnotations>,
    key_file: &str,
) -> Result<String> {
    let verification_key = read_key_file(key_file)?;
    let mut verifier = Verifier::new(sources.cloned());
    let verified_manifest_digest = verifier
        .verify(
            url,
            docker_config.cloned(),
            annotations.cloned(),
            &verification_key,
        )
        .await?;

    info!("Policy successfully verified");
    Ok(verified_manifest_digest)
}

pub(crate) async fn verify_local_checksum(
    url: &str,
    docker_config: Option<&DockerConfig>,
    sources: Option<&Sources>,
    verified_manifest_digest: &str,
) -> Result<()> {
    let mut verifier = Verifier::new(sources.cloned());
    verifier
        .verify_local_file_checksum(url, docker_config.cloned(), verified_manifest_digest)
        .await?;

    info!("Local checksum successfully verified");
    Ok(())
}

fn read_key_file(path: &str) -> Result<String> {
    let verification_key =
        fs::read_to_string(path).map_err(|e| anyhow!("Something went wrong: {:?}", e))?;
    Ok(verification_key)
}
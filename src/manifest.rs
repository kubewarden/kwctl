use anyhow::{anyhow, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};
use validator::Validate;

use policy_evaluator::policy_metadata::{Metadata, Rule};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterAdmissionPolicy {
    api_version: String,
    kind: String,
    metadata: ObjectMeta,
    spec: ClusterAdmissionPolicySpec,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterAdmissionPolicySpec {
    module: String,
    settings: serde_yaml::Mapping,
    rules: Vec<Rule>,
    mutating: bool,
}

impl TryFrom<ScaffoldData> for ClusterAdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(ClusterAdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1alpha2"),
            kind: String::from("ClusterAdmissionPolicy"),
            metadata: ObjectMeta {
                name: Some(String::from("generated-policy")),
                ..Default::default()
            },
            spec: ClusterAdmissionPolicySpec {
                module: data.uri,
                settings: data.settings,
                rules: data.metadata.rules.clone(),
                mutating: data.metadata.mutating,
            },
        })
    }
}

struct ScaffoldData {
    pub uri: String,
    metadata: Metadata,
    settings: serde_yaml::Mapping,
}

pub(crate) fn manifest(id: &str, resource_type: &str, settings: Option<String>) -> Result<()> {
    let wasm_path: PathBuf; 
    let mut uri: String = id.to_string();

    let is_sha = crate::utils::is_sha(id);
    if is_sha {
        uri = crate::utils::uri_from_sha(id)?;
        wasm_path = crate::utils::wasm_path_from_sha(id)?;
    } else {
        let uri = crate::utils::map_path_to_uri(id)?;
        wasm_path = crate::utils::wasm_path(uri.as_str())?;
    }
    let metadata = Metadata::from_path(&wasm_path)?
        .ok_or_else(||
            anyhow!(
                "No Kubewarden metadata found inside of '{}'.\nPolicies can be annotated with the `kwctl annotate` command.",
                id)
        )?;

    let settings_yml: serde_yaml::Mapping =
        serde_yaml::from_str(&settings.unwrap_or_else(|| String::from("{}")))?;

    let scaffold_data = ScaffoldData {
        uri,
        metadata,
        settings: settings_yml,
    };

    let resource = match resource_type {
        "ClusterAdmissionPolicy" => ClusterAdmissionPolicy::try_from(scaffold_data),
        other => Err(anyhow!(
            "Resource {} unknown. Valid types are: ClusterAdmissionPolicy",
            other,
        )),
    }?;

    let stdout = std::io::stdout();
    let out = stdout.lock();
    serde_yaml::to_writer(out, &resource)?;

    Ok(())
}

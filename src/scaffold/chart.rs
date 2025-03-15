use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str::FromStr,
};

use anyhow::{anyhow, Result};
use oci_spec::distribution::Reference;
use policy_evaluator::policy_metadata::{ContextAwareResource, Metadata, Rule};
use serde::Serialize;
use tracing::warn;

/// Represents the Chart.yaml file of the chart
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Chart {
    api_version: String,
    name: String,
    description: String,
    #[serde(rename = "type")]
    chart_type: String,
    home: String,
    keywords: Option<Vec<String>>,
    version: String,
    app_version: String,
    annotations: Option<BTreeMap<String, String>>,
}

/// Represents the values.yml file of the chart
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Values {
    global: Global,
    cluster_scoped: bool,
    spec: Spec,
}

#[derive(Serialize)]
struct Global {
    cattle: Cattle,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Cattle {
    system_default_registry: String,
}

/// Represents the spec.module field in the values.yml file
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Module {
    repository: String,
    tag: String,
}

/// Represents the spec field in the values.yml file
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Spec {
    module: Module,
    mode: String,
    mutating: bool,
    context_aware_resources: BTreeSet<ContextAwareResource>,
    rules: Vec<Rule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<serde_yaml::Mapping>,
}

pub(crate) fn chart(
    version: &str,
    has_settings: bool,
    metadata_path: impl AsRef<Path>,
    questions_path: Option<impl AsRef<Path>>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let metadata_yaml = std::fs::read_to_string(metadata_path)
        .map_err(|e| anyhow!("Failed to read metadata file: {}", e))?;
    let metadata: Metadata = serde_yaml::from_str(&metadata_yaml)
        .map_err(|e| anyhow!("Failed to parse metadata file: {}", e))?;

    let annotations = metadata
        .annotations
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("Missing metadata annotations"))?;

    let oci_url = annotations
        .get("io.kubewarden.policy.ociUrl")
        .ok_or_else(|| anyhow!("Missing repository annotation"))?;
    let image_ref = Reference::from_str(oci_url).map_err(|e| anyhow!("Invalid OCI URL: {}", e))?;
    let repository = image_ref.repository().to_owned();
    let registry = image_ref.registry().to_owned();

    let name = annotations
        .get("io.kubewarden.policy.title")
        .ok_or_else(|| anyhow!("Missing title annotation"))?;
    let description = annotations
        .get("io.kubewarden.policy.description")
        .ok_or_else(|| anyhow!("Missing description annotation"))?;
    let home = annotations
        .get("io.kubewarden.policy.url")
        .ok_or_else(|| anyhow!("Missing url annotation."))?;
    let keywords = annotations
        .get("io.kubewarden.policy.keywords")
        .map(|keywords| keywords.split(',').map(|s| s.trim().to_owned()).collect());

    std::fs::create_dir_all(&output_path)
        .map_err(|e| anyhow!("Failed to create directory: {}", e))?;

    // Chart.yaml
    let chart = Chart {
        api_version: "v2".to_owned(),
        name: name.to_owned(),
        description: description.to_owned(),
        chart_type: "application".to_owned(),
        home: home.to_owned(),
        keywords,
        version: version.to_owned(),
        app_version: version.to_owned(),
        annotations: metadata.annotations,
    };
    let chart_yaml =
        serde_yaml::to_string(&chart).map_err(|e| anyhow!("Failed to serialize chart: {}", e))?;
    let chart_yaml_output_path = output_path.as_ref().join("Chart.yaml");
    std::fs::write(&chart_yaml_output_path, chart_yaml.as_bytes())
        .map_err(|e| anyhow!("Failed to write chart file: {}", e))?;

    // values.yaml
    let settings = if has_settings {
        Some(serde_yaml::Mapping::new())
    } else {
        None
    };

    let values = Values {
        global: Global {
            cattle: Cattle {
                system_default_registry: registry.to_owned(),
            },
        },
        cluster_scoped: true,
        spec: Spec {
            module: Module {
                repository: repository.to_owned(),
                tag: version.to_owned(),
            },
            mode: metadata.execution_mode.to_string(),
            mutating: metadata.mutating,
            context_aware_resources: metadata.context_aware_resources.clone(),
            rules: metadata.rules.clone(),
            settings,
        },
    };
    let values_yaml =
        serde_yaml::to_string(&values).map_err(|e| anyhow!("Failed to serialize values: {}", e))?;
    let values_yaml_output_path = output_path.as_ref().join("values.yaml");
    std::fs::write(&values_yaml_output_path, values_yaml.as_bytes())
        .map_err(|e| anyhow!("Failed to write values file: {}", e))?;

    // questions.yaml
    if let Some(path) = questions_path {
        if !has_settings {
            warn!("Ignoring questions file because the policy does not have settings");
        } else {
            let questions_yaml_output_path = output_path.as_ref().join("questions.yaml");
            std::fs::copy(path, &questions_yaml_output_path)
                .map_err(|e| anyhow!("Failed to copy questions file: {}", e))?;
        }
    }

    // templates/policy.yaml
    let policy_yaml_bytes = include_bytes!("templates/policy.yaml");
    let policy_yaml_output_path = output_path.as_ref().join("templates").join("policy.yaml");
    std::fs::create_dir_all(policy_yaml_output_path.parent().unwrap())
        .map_err(|e| anyhow!("Failed to create templates directory: {}", e))?;
    std::fs::write(policy_yaml_output_path, policy_yaml_bytes)?;

    Ok(())
}

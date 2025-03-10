use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{anyhow, Result};
use policy_evaluator::policy_metadata::{ContextAwareResource, Metadata, Rule};
use serde::Serialize;

/// Represents the Chart.yaml file of the chart
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Chart {
    api_version: String,
    name: String,
    description: String,
    icon: Option<String>,
    #[serde(rename = "type")]
    chart_type: String,
    home: String,
    kube_version: String,
    keywords: Option<Vec<String>>,
    version: String,
    app_version: String,
    annotations: Option<BTreeMap<String, String>>,
}

/// Represents the values.yml file of the chart
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Values {
    cluster_scoped: bool,
    spec: Spec,
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
    settings: serde_yaml::Value,
}

pub(crate) fn chart(
    tag: &str,
    metadata_path: impl AsRef<Path>,
    questions_path: Option<impl AsRef<Path>>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    std::fs::create_dir_all(&output_path)
        .map_err(|e| anyhow!("Failed to create directory: {}", e))?;

    let metadata_yaml = std::fs::read_to_string(metadata_path)
        .map_err(|e| anyhow!("Failed to read metadata file: {}", e))?;
    let metadata: Metadata = serde_yaml::from_str(&metadata_yaml)
        .map_err(|e| anyhow!("Failed to parse metadata file: {}", e))?;

    let annotations = metadata
        .annotations
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("Missing metadata annotations"))?;

    let repository = annotations
        .get("io.kubewarden.policy.ociUrl")
        .ok_or_else(|| anyhow!("Missing repository annotation"))?;
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

    // Chart.yaml
    let chart = Chart {
        api_version: "v2".to_owned(),
        name: name.to_owned(),
        description: description.to_owned(),
        icon: None,
        chart_type: "application".to_owned(),
        home: home.to_owned(),
        kube_version: ">= 1.19.0".to_owned(),
        keywords,
        version: tag.to_owned(),
        app_version: tag.to_owned(),
        annotations: metadata.annotations,
    };
    let chart_yaml =
        serde_yaml::to_string(&chart).map_err(|e| anyhow!("Failed to serialize chart: {}", e))?;
    let chart_yaml_output_path = output_path.as_ref().join("Chart.yaml");
    std::fs::write(&chart_yaml_output_path, chart_yaml.as_bytes())
        .map_err(|e| anyhow!("Failed to write chart file: {}", e))?;

    // values.yaml
    let values = Values {
        cluster_scoped: true,
        spec: Spec {
            module: Module {
                repository: repository.to_owned(),
                tag: tag.to_owned(),
            },
            mode: metadata.execution_mode.to_string(),
            mutating: metadata.mutating,
            context_aware_resources: metadata.context_aware_resources.clone(),
            rules: metadata.rules.clone(),
            settings: serde_yaml::Value::Null,
        },
    };
    let values_yaml =
        serde_yaml::to_string(&values).map_err(|e| anyhow!("Failed to serialize values: {}", e))?;
    let values_yaml_output_path = output_path.as_ref().join("values.yaml");
    std::fs::write(&values_yaml_output_path, values_yaml.as_bytes())
        .map_err(|e| anyhow!("Failed to write values file: {}", e))?;

    // questions.yaml
    let questions_value = if let Some(questions_path) = questions_path {
        let questions_yaml = std::fs::read_to_string(questions_path)
            .map_err(|e| anyhow!("Failed to read questions file: {}", e))?;
        let questions_value: serde_yaml::Value = serde_yaml::from_str(&questions_yaml)
            .map_err(|e| anyhow!("Failed to parse questions file: {}", e))?;

        Some(questions_value)
    } else {
        None
    };
    let questions = generate_questions(questions_value)?;
    let questions_yaml = serde_yaml::to_string(&questions)
        .map_err(|e| anyhow!("Failed to serialize questions: {}", e))?;
    let questions_yaml_output_path = output_path.as_ref().join("questions.yaml");
    std::fs::write(&questions_yaml_output_path, questions_yaml.as_bytes())
        .map_err(|e| anyhow!("Failed to write questions file: {}", e))?;

    // templates/policy.yaml
    let policy_yaml_bytes = include_bytes!("templates/policy.yaml");
    let policy_yaml_output_path = output_path.as_ref().join("templates").join("policy.yaml");
    std::fs::create_dir_all(policy_yaml_output_path.parent().unwrap())
        .map_err(|e| anyhow!("Failed to create templates directory: {}", e))?;
    std::fs::write(policy_yaml_output_path, policy_yaml_bytes)?;

    Ok(())
}

// Generates the question.yml file content.
// Note:  unfortunately there is no official spec for the questions.yml file,
// so this is a best-effort implementation.
fn generate_questions(questions_value: Option<serde_yaml::Value>) -> Result<serde_yaml::Value> {
    let mut questions = build_common_questions();

    let questions_vec = if let Some(questions) = questions_value {
        questions["questions"].clone()
    } else {
        build_default_questions()["questions"].clone()
    }
    .as_sequence()
    .ok_or_else(|| anyhow!("Invalid questions format. Expected a sequence of questions"))?
    .clone();

    questions["questions"]
        .as_sequence_mut()
        .expect("Invalid questions format")
        .extend(questions_vec);

    Ok(questions)
}

/// Generates the common questions that are shared between all the policies.
fn build_common_questions() -> serde_yaml::Value {
    let yaml_str = include_str!("templates/common_questions.yaml");

    serde_yaml::from_str(yaml_str).expect("Failed to parse yaml")
}

/// Build the default questions.
/// This is used when no questions file is provided by the user.
/// It contains a multiline question that will be rendered as a yamk editor in the UI.
fn build_default_questions() -> serde_yaml::Value {
    let yaml_str = include_str!("templates/default_questions.yaml");

    serde_yaml::from_str(yaml_str).expect("Failed to parse yaml")
}

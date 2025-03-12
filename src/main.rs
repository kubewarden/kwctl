extern crate anyhow;
extern crate clap;
extern crate directories;
extern crate policy_evaluator;
#[macro_use]
extern crate prettytable;
extern crate serde_yaml;

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use itertools::Itertools;
use lazy_static::lazy_static;
use run::HostCapabilitiesMode;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use verify::VerificationAnnotations;

use crate::utils::LookupError;
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
};

use crate::load::load;
use crate::save::save;
use policy_evaluator::{
    policy_evaluator::PolicyExecutionMode,
    policy_fetcher::{
        registry::Registry,
        sigstore::{
            self,
            trust::{ManualTrustRoot, TrustRoot},
        },
        sources::{read_sources_file, Sources},
        store::DEFAULT_ROOT,
        verify::config::{read_verification_file, LatestVerificationConfig, Signature, Subject},
        PullDestination,
    },
};
use std::io::prelude::*;

use crate::utils::new_policy_execution_mode_from_str;

mod annotate;
mod backend;
mod bench;
mod callback_handler;
mod cli;
mod completions;
mod info;
mod inspect;
mod load;
mod policies;
mod pull;
mod push;
mod rm;
mod run;
mod save;
mod scaffold;
mod utils;
mod verify;

pub(crate) const KWCTL_VERIFICATION_CONFIG: &str = "verification-config.yml";
const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";

lazy_static! {
    pub(crate) static ref KWCTL_DEFAULT_VERIFICATION_CONFIG_PATH: String = {
        DEFAULT_ROOT
            .config_dir()
            .join(KWCTL_VERIFICATION_CONFIG)
            .display()
            .to_string()
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let mut term_color_support = "dumb".to_string();

    if let Ok(val) = env::var("TERM") {
        term_color_support = val
    }

    let no_color = matches
        .get_one::<bool>("no-color")
        .unwrap_or(&false)
        .to_owned();

    // Need to set this env variable to have prettytable
    // adapt the output. This can later be removed if
    // prettytable provides methods to disable color globally
    if no_color {
        unsafe {
            env::set_var("TERM", "dumb");
        }
    } else {
        unsafe {
            env::set_var("TERM", term_color_support);
        }
    }

    // setup logging
    let verbose = matches
        .get_one::<bool>("verbose")
        .unwrap_or(&false)
        .to_owned();
    let level_filter = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let filter_layer = EnvFilter::from_default_env()
        .add_directive(level_filter.into())
        .add_directive("cranelift_codegen=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("cranelift_wasm=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("hyper=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("regalloc=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("wasmtime_cache=off".parse().unwrap()) // wasmtime_cache messages are not critical and just confuse users
        .add_directive("walrus=warn".parse().unwrap()); // walrus: ignore warning messages
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(!no_color),
        )
        .init();

    match matches.subcommand_name() {
        Some("policies") => policies::list(),
        Some("info") => info::info(),
        Some("pull") => {
            if let Some(matches) = matches.subcommand_matches("pull") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                let destination = match destination {
                    Some(destination) => PullDestination::LocalFile(destination),
                    None => PullDestination::MainStore,
                };
                pull_command(uri, destination, matches).await?
            };
            Ok(())
        }
        Some("verify") => {
            if let Some(matches) = matches.subcommand_matches("verify") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let sources = remote_server_options(matches)?;
                let verification_options = verification_options(matches)?
                    .ok_or_else(|| anyhow!("could not retrieve sigstore options"))?;
                let sigstore_trust_root = build_sigstore_trust_root(matches.to_owned()).await?;
                verify::verify(
                    uri,
                    sources.as_ref(),
                    &verification_options,
                    sigstore_trust_root.clone(),
                )
                .await
                .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?;
            };
            Ok(())
        }
        Some("push") => {
            if let Some(matches) = matches.subcommand_matches("push") {
                let sources = remote_server_options(matches)?;
                let wasm_uri =
                    crate::utils::map_path_to_uri(matches.get_one::<String>("policy").unwrap())?;
                let wasm_path = crate::utils::wasm_path(wasm_uri.as_str())?;
                let uri = matches
                    .get_one::<String>("uri")
                    .map(|u| {
                        if u.starts_with("registry://") {
                            u.clone()
                        } else {
                            format!("registry://{u}")
                        }
                    })
                    .unwrap();

                debug!(
                    policy = wasm_path.to_string_lossy().to_string().as_str(),
                    destination = uri.as_str(),
                    "policy push"
                );

                let force = matches.contains_id("force");

                let immutable_ref = push::push(wasm_path, &uri, sources.as_ref(), force).await?;

                match matches.get_one::<String>("output").map(|s| s.as_str()) {
                    Some("json") => {
                        let mut response: HashMap<&str, String> = HashMap::new();
                        response.insert("immutable_ref", immutable_ref);
                        serde_json::to_writer(std::io::stdout(), &response)?
                    }
                    _ => {
                        println!("Policy successfully pushed: {immutable_ref}");
                    }
                }
            };
            Ok(())
        }
        Some("rm") => {
            if let Some(matches) = matches.subcommand_matches("rm") {
                let uri_or_sha_prefix = matches.get_one::<String>("uri_or_sha_prefix").unwrap();
                rm::rm(uri_or_sha_prefix)?;
            }
            Ok(())
        }
        Some("run") => {
            if let Some(matches) = matches.subcommand_matches("run") {
                let pull_and_run_settings = parse_pull_and_run_settings(matches).await?;
                run::pull_and_run(&pull_and_run_settings)
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "Error running policy {}: {}",
                            pull_and_run_settings.uri,
                            e.to_string()
                        )
                    })?;
            }
            Ok(())
        }
        Some("bench") => {
            if let Some(matches) = matches.subcommand_matches("bench") {
                use std::time::Duration;

                let pull_and_run_settings = parse_pull_and_run_settings(matches).await?;
                let mut benchmark_cfg = tiny_bench::BenchmarkConfig::default();

                if let Some(measurement_time) = matches.get_one::<String>("measurement_time") {
                    let duration: u64 = measurement_time.parse().map_err(|e| {
                        anyhow!("Cannot convert 'measurement-time' to seconds: {:?}", e)
                    })?;
                    benchmark_cfg.measurement_time = Duration::from_secs(duration);
                }
                if let Some(num_resamples) = matches.get_one::<String>("num_resamples") {
                    let num: usize = num_resamples.parse().map_err(|e| {
                        anyhow!("Cannot convert 'num-resamples' to number: {:?}", e)
                    })?;
                    benchmark_cfg.num_resamples = num;
                }
                if let Some(num_samples) = matches.get_one::<String>("num_samples") {
                    let num: usize = num_samples
                        .parse()
                        .map_err(|e| anyhow!("Cannot convert 'num-samples' to number: {:?}", e))?;
                    benchmark_cfg.num_resamples = num;
                }
                if let Some(warm_up_time) = matches.get_one::<String>("warm_up_time") {
                    let duration: u64 = warm_up_time.parse().map_err(|e| {
                        anyhow!("Cannot convert 'warm-up-time' to seconds: {:?}", e)
                    })?;
                    benchmark_cfg.warm_up_time = Duration::from_secs(duration);
                }
                benchmark_cfg.dump_results_to_disk = matches.contains_id("dump_results_to_disk");

                bench::pull_and_bench(&bench::PullAndBenchSettings {
                    pull_and_run_settings,
                    benchmark_cfg,
                })
                .await?;
            }
            Ok(())
        }
        Some("annotate") => {
            if let Some(matches) = matches.subcommand_matches("annotate") {
                let wasm_path = matches
                    .get_one::<String>("wasm-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let metadata_file = matches
                    .get_one::<String>("metadata-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let usage_file = matches
                    .get_one::<String>("usage-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                annotate::write_annotation(wasm_path, metadata_file, destination, usage_file)?;
            }
            Ok(())
        }
        Some("inspect") => {
            if let Some(matches) = matches.subcommand_matches("inspect") {
                let uri_or_sha_prefix = matches.get_one::<String>("uri_or_sha_prefix").unwrap();
                let output = inspect::OutputType::try_from(
                    matches.get_one::<String>("output").map(|s| s.as_str()),
                )?;
                let sources = remote_server_options(matches)?;
                let no_signatures = !matches
                    .get_one::<bool>("show-signatures")
                    .unwrap_or(&false)
                    .to_owned();
                inspect::inspect(uri_or_sha_prefix, output, sources, no_color, no_signatures)
                    .await?;
            };
            Ok(())
        }
        Some("scaffold") => {
            if let Some(scaffold_matches) = matches.subcommand_matches("scaffold") {
                match scaffold_matches.subcommand() {
                    Some(("verification-config", _)) => {
                        println!("{}", scaffold::verification_config()?);
                    }
                    Some(("artifacthub", artifacthub_matches)) => {
                        let metadata_file = artifacthub_matches
                            .get_one::<String>("metadata-path")
                            .map(|output| PathBuf::from_str(output).unwrap())
                            .unwrap();
                        let version = artifacthub_matches.get_one::<String>("version").unwrap();
                        let gh_release_tag = artifacthub_matches
                            .get_one::<String>("gh-release-tag")
                            .cloned();
                        let questions_file = artifacthub_matches
                            .get_one::<String>("questions-path")
                            .map(|output| PathBuf::from_str(output).unwrap());
                        let content = scaffold::artifacthub(
                            metadata_file,
                            version,
                            gh_release_tag.as_deref(),
                            questions_file,
                        )?;
                        if let Some(output) = artifacthub_matches.get_one::<String>("output") {
                            let output_path = PathBuf::from_str(output)?;
                            fs::write(output_path, content)?;
                        } else {
                            println!("{}", content);
                        }
                    }
                    Some(("manifest", manifest_matches)) => {
                        scaffold_manifest_command(manifest_matches).await?;
                    }
                    Some(("vap", vap_matches)) => {
                        let cel_policy_uri = vap_matches.get_one::<String>("cel-policy").unwrap();
                        let vap_file: PathBuf =
                            vap_matches.get_one::<String>("policy").unwrap().into();
                        let vap_binding_file: PathBuf =
                            vap_matches.get_one::<String>("binding").unwrap().into();

                        scaffold::vap(
                            cel_policy_uri.as_str(),
                            vap_file.as_path(),
                            vap_binding_file.as_path(),
                        )?;
                    }
                    Some(("admission-request", admission_request_matches)) => {
                        let operation: scaffold::AdmissionRequestOperation =
                            admission_request_matches
                                .get_one::<String>("operation")
                                .unwrap()
                                .parse::<scaffold::AdmissionRequestOperation>()
                                .map_err(|e| anyhow!("Error parsing operation: {}", e))?;
                        let object_path: Option<PathBuf> =
                            if admission_request_matches.contains_id("object") {
                                Some(
                                    admission_request_matches
                                        .get_one::<String>("object")
                                        .unwrap()
                                        .into(),
                                )
                            } else {
                                None
                            };
                        let old_object_path: Option<PathBuf> =
                            if admission_request_matches.contains_id("old-object") {
                                Some(
                                    admission_request_matches
                                        .get_one::<String>("old-object")
                                        .unwrap()
                                        .into(),
                                )
                            } else {
                                None
                            };

                        scaffold::admission_request(operation, object_path, old_object_path)
                            .await?;
                    }
                    Some(("chart", chart_matches)) => {
                        let version = chart_matches
                            .get_one::<String>("version")
                            .expect("version is required");
                        let metadata_path = chart_matches
                            .get_one::<PathBuf>("metadata-path")
                            .expect("metadata path is required");
                        let has_settings = !chart_matches
                            .get_one::<bool>("no-settings")
                            .expect("no-settings is required")
                            .to_owned();
                        let questions_path = chart_matches.get_one::<PathBuf>("questions-path");

                        let output_path = chart_matches
                            .get_one::<PathBuf>("output-path")
                            .expect("output path is required");

                        scaffold::chart(
                            version,
                            has_settings,
                            metadata_path,
                            questions_path,
                            output_path,
                        )?;
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        Some("completions") => {
            if let Some(matches) = matches.subcommand_matches("completions") {
                completions::completions(matches.get_one::<String>("shell").unwrap())?;
            }
            Ok(())
        }
        Some("digest") => {
            if let Some(matches) = matches.subcommand_matches("digest") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let sources = remote_server_options(matches)?;
                let registry = Registry::new();
                let digest = registry.manifest_digest(uri, sources.as_ref()).await?;
                println!("{uri}@{digest}");
            }
            Ok(())
        }
        Some("save") => {
            if let Some(matches) = matches.subcommand_matches("save") {
                let policies = matches.get_many::<String>("policies").unwrap();
                let output = matches.get_one::<String>("output").unwrap();

                save(policies.collect_vec(), output)?;
            }
            Ok(())
        }
        Some("load") => {
            if let Some(matches) = matches.subcommand_matches("load") {
                let input = matches.get_one::<String>("input").unwrap();
                load(input)?;
            }
            Ok(())
        }
        Some("docs") => {
            if let Some(matches) = matches.subcommand_matches("docs") {
                let output = matches.get_one::<String>("output").unwrap();
                let mut file = std::fs::File::create(output)
                    .map_err(|e| anyhow!("cannot create file {}: {}", output, e))?;
                let docs_content = clap_markdown::help_markdown_command(&cli::build_cli());
                file.write_all(docs_content.as_bytes())
                    .map_err(|e| anyhow!("cannot write to file {}: {}", output, e))?;
            }
            Ok(())
        }
        Some(command) => Err(anyhow!("unknown subcommand: {}", command)),
        None => {
            // NOTE: this should not happen due to
            // SubcommandRequiredElseHelp setting
            unreachable!();
        }
    }
}

fn remote_server_options(matches: &ArgMatches) -> Result<Option<Sources>> {
    let sources = if let Some(sources_path) = matches.get_one::<String>("sources-path") {
        Some(read_sources_file(Path::new(&sources_path))?)
    } else {
        let sources_path = DEFAULT_ROOT.config_dir().join("sources.yaml");
        if Path::exists(&sources_path) {
            Some(read_sources_file(&sources_path)?)
        } else {
            None
        }
    };

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        unsafe {
            env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
        }
    }
    if let Ok(docker_config_path_str) = env::var(DOCKER_CONFIG_ENV_VAR) {
        let docker_config_path = Path::new(&docker_config_path_str).join("config.json");
        match docker_config_path.as_path().try_exists() {
            Ok(exist) => {
                if !exist {
                    warn!("Docker config file not found. Check if you are pointing to the directory containing the file. The file path should be {}.", docker_config_path.display());
                }
            }
            Err(_) => {
                warn!("Docker config file not found. Check if you are pointing to the directory containing the file. The file path should be {}.", docker_config_path.display());
            }
        }
    }

    Ok(sources)
}

fn verification_options(matches: &ArgMatches) -> Result<Option<LatestVerificationConfig>> {
    if let Some(verification_config) = build_verification_options_from_flags(matches)? {
        // flags present, built configmap from them:
        if matches.contains_id("verification-config-path") {
            return Err(anyhow!(
                "verification-config-path cannot be used in conjunction with other verification flags"
            ));
        }
        return Ok(Some(verification_config));
    }
    if let Some(verification_config_path) = matches.get_one::<String>("verification-config-path") {
        // config flag present, read it:
        Ok(Some(read_verification_file(Path::new(
            &verification_config_path,
        ))?))
    } else {
        let verification_config_path = DEFAULT_ROOT.config_dir().join(KWCTL_VERIFICATION_CONFIG);
        if Path::exists(&verification_config_path) {
            // default config flag present, read it:
            info!(path = ?verification_config_path, "Default verification config present, using it");
            Ok(Some(read_verification_file(&verification_config_path)?))
        } else {
            Ok(None)
        }
    }
}

/// Takes clap flags and builds a Some(LatestVerificationConfig) containing all
/// passed pub keys and annotations in LatestVerificationConfig.AllOf.
/// If no verification flags where used, it returns a None.
fn build_verification_options_from_flags(
    matches: &ArgMatches,
) -> Result<Option<LatestVerificationConfig>> {
    let key_files: Option<Vec<String>> = matches
        .get_many::<String>("verification-key")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let annotations: Option<VerificationAnnotations> =
        match matches.get_many::<String>("verification-annotation") {
            None => None,
            Some(items) => {
                let mut values: BTreeMap<String, String> = BTreeMap::new();
                for item in items {
                    let tmp: Vec<_> = item.splitn(2, '=').collect();
                    if tmp.len() == 2 {
                        values.insert(String::from(tmp[0]), String::from(tmp[1]));
                    }
                }
                if values.is_empty() {
                    None
                } else {
                    Some(values)
                }
            }
        };

    let cert_email: Option<String> = matches
        .get_many::<String>("cert-email")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let cert_oidc_issuer: Option<String> = matches
        .get_many::<String>("cert-oidc-issuer")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    let github_owner: Option<String> = matches
        .get_many::<String>("github-owner")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());
    let github_repo: Option<String> = matches
        .get_many::<String>("github-repo")
        .map(|items| items.into_iter().map(|i| i.to_string()).collect());

    if key_files.is_none()
        && annotations.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && github_repo.is_none()
    {
        // no verification flags were used, don't create a LatestVerificationConfig
        return Ok(None);
    }

    if key_files.is_none()
        && cert_email.is_none()
        && cert_oidc_issuer.is_none()
        && github_owner.is_none()
        && annotations.is_some()
    {
        return Err(anyhow!(
            "Intending to verify annotations, but no verification keys, OIDC issuer or GitHub owner were passed"
        ));
    }

    if github_repo.is_some() && github_owner.is_none() {
        return Err(anyhow!(
            "Intending to verify GitHub actions signature, but the repository owner is missing."
        ));
    }

    let mut signatures: Vec<Signature> = Vec::new();

    if (cert_email.is_some() && cert_oidc_issuer.is_none())
        || (cert_email.is_none() && cert_oidc_issuer.is_some())
    {
        return Err(anyhow!(
            "Intending to verify OIDC issuer, but no email or issuer were provided. You must pass the email and OIDC issuer to be validated together "
        ));
    } else if cert_email.is_some() && cert_oidc_issuer.is_some() {
        let sig = Signature::GenericIssuer {
            issuer: cert_oidc_issuer.unwrap(),
            subject: Subject::Equal(cert_email.unwrap()),
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    if let Some(repo_owner) = github_owner {
        let sig = Signature::GithubAction {
            owner: repo_owner,
            repo: github_repo,
            annotations: annotations.clone(),
        };
        signatures.push(sig)
    }

    for key_path in key_files.iter().flatten() {
        let sig = Signature::PubKey {
            owner: None,
            key: fs::read_to_string(key_path)
                .map_err(|e| anyhow!("could not read file {}: {:?}", key_path, e))?
                .to_string(),
            annotations: annotations.clone(),
        };
        signatures.push(sig);
    }
    let signatures_all_of: Option<Vec<Signature>> = if signatures.is_empty() {
        None
    } else {
        Some(signatures)
    };
    let verification_config = LatestVerificationConfig {
        all_of: signatures_all_of,
        any_of: None,
    };
    Ok(Some(verification_config))
}

/// Takes clap flags and builds a Result<run::PullAndRunSettings> instance
async fn parse_pull_and_run_settings(matches: &ArgMatches) -> Result<run::PullAndRunSettings> {
    let uri_or_sha_prefix = matches.get_one::<String>("uri_or_sha_prefix").unwrap();
    let uri = crate::utils::map_path_to_uri(uri_or_sha_prefix)?;

    let request = match matches
        .get_one::<String>("request-path")
        .map(|s| s.as_str())
        .unwrap()
    {
        "-" => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| anyhow!("Error reading request from stdin: {}", e))?;
            buffer
        }
        request_path => fs::read_to_string(request_path).map_err(|e| {
            anyhow!(
                "Error opening request file {}; {}",
                matches.get_one::<String>("request-path").unwrap(),
                e
            )
        })?,
    };
    if matches.contains_id("settings-path") && matches.contains_id("settings-json") {
        return Err(anyhow!(
            "'settings-path' and 'settings-json' cannot be used at the same time"
        ));
    }
    let settings = if matches.contains_id("settings-path") {
        matches
            .get_one::<String>("settings-path")
            .map(|settings| -> Result<String> {
                fs::read_to_string(settings)
                    .map_err(|e| anyhow!("Error reading settings from {}: {}", settings, e))
            })
            .transpose()?
    } else if matches.contains_id("settings-json") {
        Some(matches.get_one::<String>("settings-json").unwrap().clone())
    } else {
        None
    };
    let sources = remote_server_options(matches)
        .map_err(|e| anyhow!("Error getting remote server options: {}", e))?;
    let execution_mode: Option<PolicyExecutionMode> =
        if let Some(mode_name) = matches.get_one::<String>("execution-mode") {
            Some(new_policy_execution_mode_from_str(mode_name)?)
        } else {
            None
        };

    let verification_options = verification_options(matches)?;
    let mut verified_manifest_digest: Option<String> = None;
    let sigstore_trust_root = build_sigstore_trust_root(matches.to_owned()).await?;
    if verification_options.is_some() {
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        verified_manifest_digest = Some(
            verify::verify(
                &uri,
                sources.as_ref(),
                verification_options.as_ref().unwrap(),
                sigstore_trust_root.clone(),
            )
            .await
            .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?,
        );
    }

    let enable_wasmtime_cache = !matches
        .get_one::<bool>("disable-wasmtime-cache")
        .unwrap_or(&false)
        .to_owned();

    let allow_context_aware_resources = matches
        .get_one::<bool>("allow-context-aware")
        .unwrap_or(&false)
        .to_owned();

    let mut host_capabilities_mode = HostCapabilitiesMode::Direct;
    if matches.contains_id("record-host-capabilities-interactions") {
        let destination = matches
            .get_one::<String>("record-host-capabilities-interactions")
            .map(|destination| PathBuf::from_str(destination).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'record-host-capabilities-interactions' file"))?;

        info!(session_file = ?destination, "host capabilities proxy enabled with record mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Record { destination });
    }
    if matches.contains_id("replay-host-capabilities-interactions") {
        let source = matches
            .get_one::<String>("replay-host-capabilities-interactions")
            .map(|source| PathBuf::from_str(source).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'replay-host-capabilities-interaction' file"))?;

        info!(session_file = ?source, "host capabilities proxy enabled with replay mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Replay { source });
    }

    let raw = matches.get_one::<bool>("raw").unwrap_or(&false).to_owned();

    Ok(run::PullAndRunSettings {
        uri,
        user_execution_mode: execution_mode,
        sources,
        request,
        raw,
        settings,
        verified_manifest_digest,
        sigstore_trust_root,
        enable_wasmtime_cache,
        allow_context_aware_resources,
        host_capabilities_mode,
    })
}

async fn build_sigstore_trust_root(
    matches: ArgMatches,
) -> Result<Option<Arc<ManualTrustRoot<'static>>>> {
    use sigstore::registry::Certificate;

    if matches.contains_id("fulcio-cert-path") || matches.contains_id("rekor-public-key-path") {
        let mut fulcio_certs: Vec<Certificate> = vec![];
        if let Some(items) = matches.get_many::<String>("fulcio-cert-path") {
            for item in items {
                let data = fs::read(item)?;
                let cert = Certificate {
                    data,
                    encoding: sigstore::registry::CertificateEncoding::Pem,
                };
                fulcio_certs.push(cert);
            }
        };

        let mut rekor_public_keys: Vec<Vec<u8>> = vec![];
        if let Some(items) = matches.get_many::<String>("rekor-public-key-path") {
            for item in items {
                let data = fs::read(item)?;
                let pem_data = pem::parse(&data)?;
                rekor_public_keys.push(pem_data.contents().to_owned());
            }
        };

        if fulcio_certs.is_empty() || rekor_public_keys.is_empty() {
            return Err(anyhow!(
                "both a fulcio certificate and a rekor public key are required"
            ));
        }
        debug!("building Sigstore trust root from flags");
        Ok(Some(Arc::new(ManualTrustRoot {
            fulcio_certs: fulcio_certs
                .iter()
                .map(|c| {
                    let cert: sigstore::registry::Certificate = c.to_owned();
                    cert.try_into()
                        .expect("could not convert certificate to CertificateDer")
                })
                .collect(),
            rekor_keys: rekor_public_keys,
            ..Default::default()
        })))
    } else {
        debug!("building Sigstore trust root from Sigstore's TUF repository");
        let checkout_path = DEFAULT_ROOT.config_dir().join("fulcio_and_rekor_data");
        if !Path::exists(&checkout_path) {
            fs::create_dir_all(checkout_path.clone())?
        }

        let repo = sigstore::trust::sigstore::SigstoreTrustRoot::new(Some(checkout_path.as_path()))
            .await?;
        let fulcio_certs: Vec<rustls_pki_types::CertificateDer> = repo
            .fulcio_certs()
            .expect("no fulcio certs found inside of TUF repository")
            .into_iter()
            .map(|c| c.into_owned())
            .collect();
        let manual_root = ManualTrustRoot {
            fulcio_certs,
            rekor_keys: repo
                .rekor_keys()
                .expect("no rekor keys found inside of TUF repository")
                .iter()
                .map(|k| k.to_vec())
                .collect(),
            ..Default::default()
        };
        Ok(Some(Arc::new(manual_root)))
    }
}

// Check if the policy is already present in the local store, and if not, pull it from the remote server.
async fn pull_if_needed(uri_or_sha_prefix: &str, matches: &ArgMatches) -> Result<()> {
    match crate::utils::get_wasm_path(uri_or_sha_prefix) {
        Err(LookupError::PolicyMissing(uri)) => {
            info!(
                "cannot find policy with uri: {}, trying to pull it from remote registry",
                uri
            );
            pull_command(&uri, PullDestination::MainStore, matches).await
        }
        Err(e) => Err(anyhow!("{}", e)),
        Ok(_path) => Ok(()),
    }
}

// Pulls a policy from a remote server and verifies it if verification options are provided.
async fn pull_command(
    uri: &String,
    destination: PullDestination,
    matches: &ArgMatches,
) -> Result<()> {
    let sources = remote_server_options(matches)?;

    let verification_options = verification_options(matches)?;
    let mut verified_manifest_digest: Option<String> = None;
    if verification_options.is_some() {
        let sigstore_trust_root = build_sigstore_trust_root(matches.to_owned()).await?;
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        verified_manifest_digest = Some(
            verify::verify(
                uri,
                sources.as_ref(),
                verification_options.as_ref().unwrap(),
                sigstore_trust_root.clone(),
            )
            .await
            .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?,
        );
    }

    let policy = pull::pull(uri, sources.as_ref(), destination).await?;

    if verification_options.is_some() {
        let sigstore_trust_root = build_sigstore_trust_root(matches.to_owned()).await?;
        return verify::verify_local_checksum(
            &policy,
            sources.as_ref(),
            &verified_manifest_digest.unwrap(),
            sigstore_trust_root.clone(),
        )
        .await;
    }
    Ok(())
}

/*
 * Scaffold a manifest from a policy.
 * This function will pull the policy if it is not already present in the local store.
 */
async fn scaffold_manifest_command(matches: &ArgMatches) -> Result<()> {
    let uri_or_sha_prefix = matches.get_one::<String>("uri_or_sha_prefix").unwrap();

    pull_if_needed(uri_or_sha_prefix, matches).await?;

    let resource_type = matches.get_one::<String>("type").unwrap();
    if matches.contains_id("settings-path") && matches.contains_id("settings-json") {
        return Err(anyhow!(
            "'settings-path' and 'settings-json' cannot be used at the same time"
        ));
    }
    let settings = if matches.contains_id("settings-path") {
        matches
            .get_one::<String>("settings-path")
            .map(|settings| -> Result<String> {
                fs::read_to_string(settings)
                    .map_err(|e| anyhow!("Error reading settings from {}: {}", settings, e))
            })
            .transpose()?
    } else if matches.contains_id("settings-json") {
        Some(matches.get_one::<String>("settings-json").unwrap().clone())
    } else {
        None
    };
    let policy_title = matches.get_one::<String>("title").cloned();

    let allow_context_aware_resources = matches
        .get_one::<bool>("allow-context-aware")
        .unwrap_or(&false)
        .to_owned();

    scaffold::manifest(
        uri_or_sha_prefix,
        resource_type.parse()?,
        settings.as_deref(),
        policy_title.as_deref(),
        allow_context_aware_resources,
    )
}

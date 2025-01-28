use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use tiny_bench::{bench_with_configuration_labeled, BenchmarkConfig};
use tracing::error;

use crate::{
    cli::configs::pull_and_run::{
        parse_policy_definitions, parse_pull_and_run_settings, PullAndRunSettings,
    },
    run::{evaluator::Evaluator, local_data::LocalData, policy_definition::PolicyDefinition},
};

pub(crate) async fn exec(matches: &ArgMatches) -> Result<()> {
    let policy_definitions = parse_policy_definitions(matches)?;
    let pull_and_run_settings = parse_pull_and_run_settings(matches, &policy_definitions).await?;
    let local_data = LocalData::new(&policy_definitions, &pull_and_run_settings).await?;
    let benchmark_config = create_benchmark_config(matches)?;

    for policy_definition in &policy_definitions {
        pull_and_bench(
            policy_definition,
            &pull_and_run_settings,
            &local_data,
            &benchmark_config,
        )
        .await
        .map_err(|e| anyhow!("[{}] - {}", policy_definition, e))?;
    }

    Ok(())
}

pub(crate) async fn pull_and_bench(
    policy_definition: &PolicyDefinition,
    pull_and_run_settings: &PullAndRunSettings,
    local_data: &LocalData,
    benchmark_config: &BenchmarkConfig,
) -> Result<()> {
    let (mut evaluator, callback_handler, shutdown_channel_tx) =
        Evaluator::new(policy_definition, pull_and_run_settings, local_data).await?;

    // start the callback handler
    let handler = tokio::spawn(async { callback_handler.loop_eval().await });

    // validate the settings given by the user
    let settings_validation_response = evaluator.validate_settings();
    if !settings_validation_response.valid {
        println!("{}", serde_json::to_string(&settings_validation_response)?);
        return Err(anyhow!(
            "[{}] - provided settings are not valid: {:?}",
            policy_definition,
            settings_validation_response.message
        ));
    }

    // We have to wrap the settings validation in a `tokio::task::block_in_place` context
    // because if the policy uses context aware functions, this would lead to blocking the
    // tokio runtime. Remember, we're running inside of an async context.
    tokio::task::block_in_place(|| {
        bench_with_configuration_labeled("validate_settings", benchmark_config, || {
            let _settings_validation_response = evaluator.validate_settings();
        });
    });

    // We have to wrap the evaluation code inside of a `tokio::task::block_in_place` context
    // because if the policy uses context aware functions, this would lead to blocking the
    // tokio runtime. Remember, we're running inside of an async context.
    tokio::task::block_in_place(|| {
        bench_with_configuration_labeled("validate", benchmark_config, || {
            let _evaluation_result = evaluator.evaluate();
        });
    });

    if shutdown_channel_tx.send(()).is_err() {
        error!("Cannot shut down the CallbackHandler task");
    } else if let Err(e) = handler.await {
        error!(
            error = e.to_string().as_str(),
            "Error waiting for the CallbackHandler task"
        );
    }

    Ok(())
}

fn create_benchmark_config(matches: &ArgMatches) -> Result<tiny_bench::BenchmarkConfig> {
    let mut benchmark_cfg = tiny_bench::BenchmarkConfig::default();

    if let Some(measurement_time) = matches.get_one::<String>("measurement_time") {
        let duration: u64 = measurement_time
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'measurement-time' to seconds: {:?}", e))?;
        benchmark_cfg.measurement_time = Duration::from_secs(duration);
    }
    if let Some(num_resamples) = matches.get_one::<String>("num_resamples") {
        let num: usize = num_resamples
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'num-resamples' to number: {:?}", e))?;
        benchmark_cfg.num_resamples = num;
    }
    if let Some(num_samples) = matches.get_one::<String>("num_samples") {
        let num: usize = num_samples
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'num-samples' to number: {:?}", e))?;
        benchmark_cfg.num_resamples = num;
    }
    if let Some(warm_up_time) = matches.get_one::<String>("warm_up_time") {
        let duration: u64 = warm_up_time
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'warm-up-time' to seconds: {:?}", e))?;
        benchmark_cfg.warm_up_time = Duration::from_secs(duration);
    }
    benchmark_cfg.dump_results_to_disk = matches.contains_id("dump_results_to_disk");

    Ok(benchmark_cfg)
}

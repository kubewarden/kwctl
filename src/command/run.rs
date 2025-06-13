use anyhow::{anyhow, Result};
use tracing::{error, warn};

use crate::{
    config::{policy_definition::PolicyDefinition, pull_and_run::PullAndRunSettings},
    run::{evaluator::Evaluator, local_data::LocalData},
};

pub(crate) async fn exec(
    policy_definitions: &[PolicyDefinition],
    pull_and_run_settings: &PullAndRunSettings,
) -> Result<()> {
    let local_data = LocalData::new(policy_definitions, pull_and_run_settings).await?;

    if policy_definitions.len() > 1 {
        warn!("Multiple policies defined inside of the CRD file. All of them will run sequentially using the same request.");
    }

    for policy_definition in policy_definitions {
        let (mut evaluator, callback_handler, shutdown_channel_tx) =
            Evaluator::new(policy_definition, pull_and_run_settings, &local_data).await?;

        // start the callback handler
        let handler = tokio::spawn(async { callback_handler.loop_eval().await });

        // We have to wrap the evaluation code inside of a `tokio::task::block_in_place` context
        // because if the policy uses context aware functions, this would lead to blocking the
        // tokio runtime. Remember, we're running inside of an async context.
        let evaluation_result = tokio::task::block_in_place(move || {
            // validate the settings given by the user
            let settings_validation_response = evaluator.validate_settings();
            if !settings_validation_response.valid {
                return Err(anyhow!(
                    "Provided settings are not valid: {:?}",
                    settings_validation_response.message.unwrap_or_default()
                ));
            }

            Ok(evaluator.evaluate())
        });

        if shutdown_channel_tx.send(()).is_err() {
            error!("Cannot shut down the CallbackHandler task");
        } else if let Err(e) = handler.await {
            error!(
                error = e.to_string().as_str(),
                "Error waiting for the CallbackHandler task"
            );
        }

        println!("{}", serde_json::to_string(&evaluation_result?)?);
    }

    Ok(())
}

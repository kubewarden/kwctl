use std::path::Path;

use anyhow::{anyhow, Result};
use policy_evaluator::{policy_evaluator::PolicyExecutionMode, policy_metadata::Metadata};

use crate::backend::BackendDetector;

/// Determines the policy execution mode based on the provided metadata,
pub(crate) fn determine_execution_mode(
    metadata: Option<&Metadata>,
    user_execution_mode: Option<PolicyExecutionMode>,
    backend_detector: BackendDetector,
    wasm_path: &Path,
) -> Result<PolicyExecutionMode> {
    // Desired behaviour, as documented here: https://github.com/kubewarden/kwctl/issues/58
    //
    // When a wasm file is annotated:
    // *  if the user didn't specify a runtime to be used: kwctl will use
    //    this information to pick the right runtime
    // *  if the user specified a runtime to be used: we error out if the
    //    value provided by the user does not match with the one
    //    inside of the wasm metadata
    //
    //When a wasm file is NOT annotated:
    // * If the user didn't specify a runtime to be used:
    //   - We do a quick heuristic to understand if the policy is Rego base:
    //      - If we do not find the OPA ABI constant -> we assume the policy is
    //        a kubewarden one
    //      - If we do find the policy was built using Rego, kwctl exists with
    //        an error because the user has to specify whether this is a OPA
    //        or Gatekeeper policy (that influences how kwctl builds the input and
    //        data variables)
    // * If the user does provide the --runtime-mode flag: we use the runtime
    //   the user specified

    match metadata {
        Some(metadata) => {
            // metadata is set
            match user_execution_mode {
                Some(usermode) => {
                    // metadata AND user execution mode are set
                    if usermode != metadata.execution_mode {
                        Err(anyhow!(
                        "The policy execution mode specified via CLI flag is different from the one reported inside of policy's metadata. Metadata reports {} instead of {}",
                        metadata.execution_mode,
                        usermode)
                    )
                    } else {
                        Ok(metadata.execution_mode)
                    }
                }
                None => {
                    // only metadata is set
                    Ok(metadata.execution_mode)
                }
            }
        }
        None => {
            // metadata is not set
            let is_rego_policy = backend_detector.is_rego_policy(wasm_path)?;
            match user_execution_mode {
                Some(PolicyExecutionMode::Wasi) => Ok(PolicyExecutionMode::Wasi),
                Some(PolicyExecutionMode::Opa) => {
                    if is_rego_policy {
                        Ok(PolicyExecutionMode::Opa)
                    } else {
                        Err(anyhow!("The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                Some(PolicyExecutionMode::OpaGatekeeper) => {
                    if is_rego_policy {
                        Ok(PolicyExecutionMode::OpaGatekeeper)
                    } else {
                        Err(anyhow!("The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                Some(PolicyExecutionMode::KubewardenWapc) => {
                    if !is_rego_policy {
                        Ok(PolicyExecutionMode::KubewardenWapc)
                    } else {
                        Err(anyhow!("The policy has been created with Rego, the policy execution mode specified via CLI flag is wrong"))
                    }
                }
                None => {
                    if is_rego_policy {
                        Err(anyhow!("The policy has been created with Rego, please specify which Opa runtime has to be used"))
                    } else {
                        Ok(PolicyExecutionMode::KubewardenWapc)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_evaluator::ProtocolVersion;
    use std::path::PathBuf;

    fn mock_protocol_version_detector_v1(_wasm_path: PathBuf) -> Result<ProtocolVersion> {
        Ok(ProtocolVersion::V1)
    }

    fn mock_rego_policy_detector_true(_wasm_path: PathBuf) -> Result<bool> {
        Ok(true)
    }

    fn mock_rego_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    #[test]
    fn test_determine_execution_mode_metadata_and_user_mode_are_set_but_have_different_values() {
        let user_execution_mode = Some(PolicyExecutionMode::Opa);
        let metadata = Some(Metadata {
            execution_mode: PolicyExecutionMode::KubewardenWapc,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata.as_ref(),
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_err());
    }

    #[test]
    fn test_determine_execution_mode_metadata_and_user_mode_are_set_and_have_same_value() {
        let user_execution_mode = Some(PolicyExecutionMode::Opa);
        let metadata = Some(Metadata {
            execution_mode: PolicyExecutionMode::Opa,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata.as_ref(),
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_ok());
        assert_eq!(PolicyExecutionMode::Opa, mode.unwrap());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_set_and_user_mode_is_not_set() {
        let user_execution_mode = None;
        let expected_execution_mode = PolicyExecutionMode::Opa;
        let metadata = Some(Metadata {
            execution_mode: expected_execution_mode,
            ..Default::default()
        });

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let mode = determine_execution_mode(
            metadata.as_ref(),
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );
        assert!(mode.is_ok());
        assert_eq!(expected_execution_mode, mode.unwrap());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_set_but_the_user_value_is_wrong(
    ) {
        for mode in [
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode);
            let metadata = None;

            let backend_detector = match mode {
                PolicyExecutionMode::Opa => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::OpaGatekeeper => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::KubewardenWapc => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::Wasi => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
            };

            let actual = determine_execution_mode(
                metadata,
                user_execution_mode,
                backend_detector,
                &PathBuf::from("irrelevant.wasm").to_path_buf(),
            );
            assert!(
                actual.is_err(),
                "Expected to fail when user specified mode to be {}",
                mode
            );
        }
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_set_and_the_user_value_is_right(
    ) {
        for mode in [
            PolicyExecutionMode::Opa,
            PolicyExecutionMode::OpaGatekeeper,
            PolicyExecutionMode::KubewardenWapc,
        ] {
            let user_execution_mode = Some(mode);
            let metadata = None;

            let backend_detector = match mode {
                PolicyExecutionMode::Opa => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::OpaGatekeeper => BackendDetector::new(
                    mock_rego_policy_detector_true,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::KubewardenWapc => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
                PolicyExecutionMode::Wasi => BackendDetector::new(
                    mock_rego_policy_detector_false,
                    mock_protocol_version_detector_v1,
                ),
            };

            let actual = determine_execution_mode(
                metadata,
                user_execution_mode,
                backend_detector,
                &PathBuf::from("irrelevant.wasm").to_path_buf(),
            );
            assert!(
                actual.is_ok(),
                "Expected to be ok when user specified mode to be {}",
                mode
            );
            let actual = actual.unwrap();
            assert_eq!(
                actual, mode,
                "Expected to obtain {}, got {} instead",
                mode, actual,
            );
        }
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_not_set_and_policy_is_rego(
    ) {
        let user_execution_mode = None;
        let metadata = None;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
        );

        let actual = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm").to_path_buf(),
        );
        assert!(actual.is_err());
    }

    #[test]
    fn test_determine_execution_mode_metadata_is_not_set_and_user_mode_is_not_set_and_policy_is_not_rego(
    ) {
        let user_execution_mode = None;
        let metadata = None;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
        );

        let actual = determine_execution_mode(
            metadata,
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm").to_path_buf(),
        );
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), PolicyExecutionMode::KubewardenWapc);
    }
}

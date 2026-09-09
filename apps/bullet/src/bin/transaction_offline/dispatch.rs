//! Fail-closed command routing for the offline component binary.

const SYNTHETIC_FLAG: &str = "--synthetic-selection";
const JSON_FLAG: &str = "--json";
const PUBLIC_COMMAND_SOURCE_ENV: &str = "BULLET_COMMAND_CLAIM_FD";
const PUBLIC_COMMAND_MANIFEST_ENV: &str = "BULLET_COMMAND_BINARY_MANIFEST_DIGEST";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Ordinary,
    #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
    SyntheticSelection,
}

fn route(args: &[std::ffi::OsString], public_worker: bool) -> Result<Route, String> {
    match args {
        [] => Ok(Route::Ordinary),
        [synthetic, json] if synthetic == SYNTHETIC_FLAG && json == JSON_FLAG => {
            if public_worker {
                return Err("SYNTHETIC_DOGFOOD_NOT_PUBLIC".into());
            }
            #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
            {
                Ok(Route::SyntheticSelection)
            }
            #[cfg(not(all(feature = "synthetic-dogfood", debug_assertions)))]
            {
                Err("SYNTHETIC_DOGFOOD_UNAVAILABLE".into())
            }
        }
        _ => Err("TRANSACTION_OFFLINE_ARGUMENTS_INVALID".into()),
    }
}

pub(crate) async fn run() -> Result<(), String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let public_worker = std::env::var_os(PUBLIC_COMMAND_SOURCE_ENV).is_some()
        || std::env::var_os(PUBLIC_COMMAND_MANIFEST_ENV).is_some();
    match route(&args, public_worker)? {
        Route::Ordinary => super::app::run().await,
        #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
        Route::SyntheticSelection => super::synthetic_selection::run().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_invocation_is_unchanged() {
        assert_eq!(route(&[], false), Ok(Route::Ordinary));
    }

    #[test]
    fn public_worker_refuses_synthetic_before_dispatch() {
        let args = vec![SYNTHETIC_FLAG.into(), JSON_FLAG.into()];
        assert_eq!(
            route(&args, true).unwrap_err(),
            "SYNTHETIC_DOGFOOD_NOT_PUBLIC"
        );
    }

    #[test]
    fn unknown_shapes_refuse() {
        assert_eq!(
            route(&[SYNTHETIC_FLAG.into()], false).unwrap_err(),
            "TRANSACTION_OFFLINE_ARGUMENTS_INVALID"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_refuses_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        assert_eq!(
            route(&[invalid], false).unwrap_err(),
            "TRANSACTION_OFFLINE_ARGUMENTS_INVALID"
        );
    }

    #[cfg(all(feature = "synthetic-dogfood", debug_assertions))]
    #[test]
    fn debug_feature_admits_only_the_exact_synthetic_shape() {
        let args = vec![SYNTHETIC_FLAG.into(), JSON_FLAG.into()];
        assert_eq!(route(&args, false), Ok(Route::SyntheticSelection));
    }

    #[cfg(not(all(feature = "synthetic-dogfood", debug_assertions)))]
    #[test]
    fn absent_seam_refuses_synthetic() {
        let args = vec![SYNTHETIC_FLAG.into(), JSON_FLAG.into()];
        assert_eq!(
            route(&args, false).unwrap_err(),
            "SYNTHETIC_DOGFOOD_UNAVAILABLE"
        );
    }
}

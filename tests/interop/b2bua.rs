use super::{
    applications::{scenario, Outcome},
    TestResult,
};
macro_rules! case {
    ($name:ident, $transport:literal, $outcome:ident) => {
        #[tokio::test]
        #[ignore = "requires standalone B2BUA and two PJSUA peers; use scripts/interop/run.sh b2bua"]
        async fn $name() -> TestResult { scenario("b2bua", stringify!($name), $transport, Outcome::$outcome).await }
    };
}
case!(udp_caller_bye, "udp", CallerBye);
case!(udp_callee_bye, "udp", CalleeBye);
case!(udp_busy, "udp", Busy);
case!(udp_cancel, "udp", Cancel);
case!(tcp_caller_bye, "tcp", CallerBye);
case!(tcp_callee_bye, "tcp", CalleeBye);
case!(tcp_busy, "tcp", Busy);
case!(tcp_cancel, "tcp", Cancel);

#[tokio::test]
#[ignore = "requires B2BUA, PJSUA and SIPp; use scripts/interop/run.sh b2bua"]
async fn udp_sipp_late_200_after_cancel() -> TestResult {
    super::applications::late_200("b2bua", "udp_sipp_late_200_after_cancel", "udp").await
}
#[tokio::test]
#[ignore = "requires B2BUA, PJSUA and SIPp; use scripts/interop/run.sh b2bua"]
async fn tcp_sipp_late_200_after_cancel() -> TestResult {
    super::applications::late_200("b2bua", "tcp_sipp_late_200_after_cancel", "tcp").await
}

#[tokio::test]
#[ignore = "requires B2BUA, PJSUA and SIPp; use scripts/interop/run.sh b2bua"]
async fn udp_sipp_lost_bye_response() -> TestResult {
    super::applications::lost_bye_response("b2bua", "udp_sipp_lost_bye_response").await
}

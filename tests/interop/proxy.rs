use super::{
    applications::{scenario, Outcome},
    TestResult,
};
macro_rules! case {
    ($name:ident, $transport:literal, $outcome:ident) => {
        #[tokio::test]
        #[ignore = "requires standalone proxy and two PJSUA peers; use scripts/interop/run.sh proxy"]
        async fn $name() -> TestResult { scenario("proxy", stringify!($name), $transport, Outcome::$outcome).await }
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
#[ignore = "requires proxy, PJSUA and SIPp; use scripts/interop/run.sh proxy"]
async fn udp_sipp_late_200_after_cancel() -> TestResult {
    super::applications::late_200("proxy", "udp_sipp_late_200_after_cancel", "udp").await
}
#[tokio::test]
#[ignore = "requires proxy, PJSUA and SIPp; use scripts/interop/run.sh proxy"]
async fn tcp_sipp_late_200_after_cancel() -> TestResult {
    super::applications::late_200("proxy", "tcp_sipp_late_200_after_cancel", "tcp").await
}

#[tokio::test]
#[ignore = "requires proxy, PJSUA and SIPp; use scripts/interop/run.sh proxy"]
async fn udp_sipp_lost_bye_response() -> TestResult {
    super::applications::lost_bye_response("proxy", "udp_sipp_lost_bye_response").await
}

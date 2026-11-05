//! Single-datagram faults with an independent PJSUA peer and normal SIP timers.
use super::{scenario_with_faults, Outcome};
use crate::interop::{
    faults::{Action, Direction, Rule},
    TestResult,
};
use rsipstack::sip::Method;

macro_rules! cases {
    ($(($name:ident, $caller:literal, $outcome:ident, $direction:ident, $method:ident, $status:expr, $action:expr)),* $(,)?) => {$ (
        #[tokio::test]
        #[ignore = "requires PJSUA; use scripts/interop/run.sh faults"]
        async fn $name() -> TestResult {
            scenario_with_faults(stringify!($name), "udp", $caller, Outcome::$outcome,
                Some(vec![Rule::new("packet", Direction::$direction, Method::$method, $status, 1, $action)])).await
        }
    )*};
}

cases! {
    (udp_drop_outgoing_invite, true, LocalBye, Send, Invite, None, Action::Drop),
    (udp_drop_incoming_invite, false, LocalBye, Receive, Invite, None, Action::Drop),
    (udp_drop_incoming_invite_200, true, LocalBye, Receive, Invite, Some(200), Action::Drop),
    (udp_drop_outgoing_invite_200, false, LocalBye, Send, Invite, Some(200), Action::Drop),
    (udp_drop_outgoing_ack, true, LocalBye, Send, Ack, None, Action::Drop),
    (udp_drop_incoming_ack, false, LocalBye, Receive, Ack, None, Action::Drop),
    (udp_drop_outgoing_bye, true, LocalBye, Send, Bye, None, Action::Drop),
    (udp_drop_incoming_bye, true, PeerBye, Receive, Bye, None, Action::Drop),
    (udp_drop_incoming_bye_200, true, LocalBye, Receive, Bye, Some(200), Action::Drop),
    (udp_drop_outgoing_bye_200, true, PeerBye, Send, Bye, Some(200), Action::Drop),
    (udp_drop_outgoing_cancel, true, Cancel, Send, Cancel, None, Action::Drop),
    (udp_drop_incoming_cancel, false, Cancel, Receive, Cancel, None, Action::Drop),
    (udp_drop_incoming_cancel_200, true, Cancel, Receive, Cancel, Some(200), Action::Drop),
    (udp_drop_outgoing_cancel_200, false, Cancel, Send, Cancel, Some(200), Action::Drop),
    (udp_drop_incoming_invite_487, true, Cancel, Receive, Invite, Some(487), Action::Drop),
    (udp_drop_outgoing_invite_487, false, Cancel, Send, Invite, Some(487), Action::Drop),
    (udp_delay_outgoing_ack, true, LocalBye, Send, Ack, None, Action::Delay(150)),
    (udp_delay_incoming_ack, false, LocalBye, Receive, Ack, None, Action::Delay(150)),
    (udp_delay_outgoing_bye, true, LocalBye, Send, Bye, None, Action::Delay(150)),
    (udp_delay_incoming_bye, true, PeerBye, Receive, Bye, None, Action::Delay(150)),
}

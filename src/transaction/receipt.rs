//! Optional receive timestamps travel alongside the existing public event
//! channel. The public TransactionEvent API and its ordering stay unchanged.
use crate::dialog::lifecycle::LifecycleTime;
use crate::platform::sync::Mutex;
use crate::sip::SipMessage;
use alloc::collections::VecDeque;

pub(crate) struct ReceiptTimes(Mutex<VecDeque<(SipMessage, LifecycleTime)>>);

impl Default for ReceiptTimes {
    fn default() -> Self {
        Self(Mutex::new(VecDeque::new()))
    }
}

impl ReceiptTimes {
    pub fn record(&self, message: &SipMessage, time: LifecycleTime) {
        self.0.lock().push_back((message.clone(), time));
    }

    pub fn take(&self, message: &SipMessage) -> Option<LifecycleTime> {
        let mut receipts = self.0.lock();
        // Direct user injection into tu_sender has no endpoint receipt. It must
        // not consume the timestamp of a different network-delivered message.
        let index = receipts.iter().position(|(m, _)| m == message)?;
        receipts.remove(index).map(|(_, time)| time)
    }
}

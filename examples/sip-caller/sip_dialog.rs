/// SIP 对话处理模块
///
/// 处理 SIP 对话状态变化和会话管理
use rsipstack::dialog::{client_dialog::ClientInviteDialog, dialog::DialogState};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// 处理对话状态变化
///
/// 异步监听对话状态变化，处理振铃、确认、终止等事件
///
/// # 参数
/// - `_dialog`: 客户端邀请对话的 Arc 引用（当前未使用）
/// - `state_receiver`: 对话状态接收器
/// - `rtp_cancel`: RTP 取消令牌，用于在对话终止时停止 RTP 流
///
/// # 状态处理
/// - `Confirmed`: 对话已确认，通话建立
/// - `Terminated`: 对话已终止，通话结束
/// - `Early`: 振铃中（180 Ringing）
/// - 其他状态：仅记录日志
pub async fn process_dialog(
    _dialog: Arc<ClientInviteDialog>,
    mut state_receiver: UnboundedReceiver<DialogState>,
    rtp_cancel: CancellationToken,
) {
    while let Some(state) = state_receiver.recv().await {
        match &state {
            DialogState::Confirmed(_, _) => {
                info!("✅ 对话已确认，通话已建立");
            }
            DialogState::Terminated(_, reason) => {
                info!("📴 对话已终止 (原因: {:?})", reason);
                rtp_cancel.cancel();
                break;
            }
            DialogState::Early(_, resp) => {
                info!("📲 振铃中 (状态码: {})", resp.status_code);
            }
            _ => {
                debug!("对话状态变更");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_module_exists() {
        // 简单的编译时测试，确保模块可用
        assert!(true);
    }
}

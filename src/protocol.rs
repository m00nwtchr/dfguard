use bytes::BytesMut;
use std::time::Duration;

pub use crate::types::{
    BlockingState, CommandClass, FrameInfo, SessionState, StickyState, TrackingState, TxnState,
    WatchState,
};
use anyhow::{Context, Result, anyhow, bail};

pub fn parse_command_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        b'*' => parse_array_frame(buf),
        b'+' | b'-' | b':' | b'$' => bail!("unsupported frame type from client"),
        _ => parse_inline_frame(buf),
    }
}

pub fn parse_inline_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let Some(line_end) = find_crlf(buf) else {
        return Ok(None);
    };
    let line = &buf[..line_end];
    let mut iter = line
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty());
    let cmd = iter.next().ok_or_else(|| anyhow!("empty inline command"))?;
    let is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
    let command = to_upper_ascii_string(cmd);
    let args = iter.take(8).map(to_upper_ascii_string).collect();
    Ok(Some(FrameInfo {
        len: line_end + 2,
        is_auth,
        command,
        args,
    }))
}

pub fn parse_array_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let mut idx = 1;
    let Some(line_end) = find_crlf_from(buf, idx) else {
        return Ok(None);
    };
    let count = parse_number(&buf[idx..line_end])?;
    if count <= 0 {
        bail!("invalid array length");
    }
    idx = line_end + 2;

    let mut is_auth = false;
    let mut command = String::new();
    let mut args = Vec::new();
    for i in 0..count {
        if idx >= buf.len() {
            return Ok(None);
        }
        if buf[idx] != b'$' {
            bail!("unsupported array element type");
        }
        idx += 1;
        let Some(bulk_len_end) = find_crlf_from(buf, idx) else {
            return Ok(None);
        };
        let bulk_len = parse_number(&buf[idx..bulk_len_end])?;
        if bulk_len < 0 {
            bail!("null bulk not supported for command");
        }
        let bulk_len = usize::try_from(bulk_len).context("bulk length too large")?;
        idx = bulk_len_end + 2;
        if idx + bulk_len + 2 > buf.len() {
            return Ok(None);
        }
        if i == 0 {
            let cmd = &buf[idx..idx + bulk_len];
            is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
            command = to_upper_ascii_string(cmd);
        } else if args.len() < 8 {
            args.push(to_upper_ascii_string(&buf[idx..idx + bulk_len]));
        }
        idx += bulk_len + 2;
    }

    Ok(Some(FrameInfo {
        len: idx,
        is_auth,
        command,
        args,
    }))
}

pub fn parse_resp_frame_len(buf: &[u8]) -> Result<Option<usize>> {
    parse_resp_frame_len_from(buf, 0)
}

pub fn parse_resp_frame_len_from(buf: &[u8], start: usize) -> Result<Option<usize>> {
    if start >= buf.len() {
        return Ok(None);
    }

    match buf[start] {
        b'+' | b'-' | b':' | b',' | b'(' | b'#' => Ok(parse_resp_line_len(buf, start)),
        b'_' => {
            if start + 3 > buf.len() {
                return Ok(None);
            }
            if &buf[start + 1..start + 3] == b"\r\n" {
                Ok(Some(3))
            } else {
                bail!("invalid RESP null frame")
            }
        }
        b'$' => parse_resp_sized_payload_len(buf, start, -1, "invalid bulk length"),
        b'=' | b'!' => parse_resp_sized_payload_len(buf, start, 0, "invalid payload length"),
        b'*' | b'~' | b'>' | b'|' => parse_resp_aggregate_len(buf, start, 1),
        b'%' => parse_resp_aggregate_len(buf, start, 2),
        _ => bail!("unsupported RESP response type"),
    }
}

fn parse_resp_line_len(buf: &[u8], start: usize) -> Option<usize> {
    let line_end = find_crlf_from(buf, start + 1)?;
    Some(line_end + 2 - start)
}

fn parse_resp_sized_payload_len(
    buf: &[u8],
    start: usize,
    min_allowed: i64,
    invalid_msg: &str,
) -> Result<Option<usize>> {
    let Some(line_end) = find_crlf_from(buf, start + 1) else {
        return Ok(None);
    };
    let payload_len = parse_number(&buf[start + 1..line_end])?;
    if min_allowed == -1 && payload_len == -1 {
        return Ok(Some(line_end + 2 - start));
    }
    if payload_len < min_allowed {
        bail!("{invalid_msg}");
    }
    let payload_len = usize::try_from(payload_len).context("payload length too large")?;
    let total = line_end + 2 + payload_len + 2;
    if total > buf.len() {
        return Ok(None);
    }
    Ok(Some(total - start))
}

fn parse_resp_aggregate_len(
    buf: &[u8],
    start: usize,
    child_multiplier: usize,
) -> Result<Option<usize>> {
    let Some(line_end) = find_crlf_from(buf, start + 1) else {
        return Ok(None);
    };

    let count = parse_number(&buf[start + 1..line_end])?;
    if count == -1 {
        return Ok(Some(line_end + 2 - start));
    }
    if count < -1 {
        bail!("invalid aggregate length");
    }

    let count = usize::try_from(count).context("aggregate length too large")?;
    let children = count
        .checked_mul(child_multiplier)
        .ok_or_else(|| anyhow!("aggregate length too large"))?;

    let mut idx = line_end + 2;
    for _ in 0..children {
        let Some(next_len) = parse_resp_frame_len_from(buf, idx)? else {
            return Ok(None);
        };
        idx += next_len;
    }
    Ok(Some(idx - start))
}

pub fn classify_command(frame: &FrameInfo) -> CommandClass {
    let cmd = frame.command.as_str();
    match cmd {
        "MULTI" | "WATCH" | "UNWATCH" | "EXEC" | "DISCARD" | "RESET" => CommandClass::PinTemporary,
        "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" | "MONITOR" | "SELECT" => {
            CommandClass::PinForever
        }
        "BLPOP" | "BRPOP" | "BRPOPLPUSH" | "BZPOPMIN" | "BZPOPMAX" => {
            CommandClass::PinWhileBlocking
        }
        "CLIENT" if frame.args.first().is_some_and(|arg| arg == "TRACKING") => {
            CommandClass::PinTemporary
        }
        "XREAD" | "XREADGROUP" if frame.args.iter().any(|arg| arg == "BLOCK") => {
            CommandClass::PinWhileBlocking
        }
        _ => CommandClass::Stateless,
    }
}

pub fn apply_command_state_before_send(
    state: &mut SessionState,
    _frame: &FrameInfo,
    class: CommandClass,
) {
    match class {
        CommandClass::PinWhileBlocking => state.blocking = BlockingState::Waiting,
        CommandClass::Stateless | CommandClass::PinTemporary | CommandClass::PinForever => {}
    }
}

pub fn apply_command_state_after_response(
    state: &mut SessionState,
    frame: &FrameInfo,
    class: CommandClass,
    response: &[u8],
) {
    if matches!(class, CommandClass::PinWhileBlocking) && !response.is_empty() {
        state.blocking = BlockingState::Idle;
    }

    if is_error_response(response) {
        return;
    }

    let cmd = frame.command.as_str();
    match class {
        CommandClass::PinForever => state.sticky = StickyState::On,
        CommandClass::PinWhileBlocking | CommandClass::PinTemporary | CommandClass::Stateless => {}
    }

    match cmd {
        "MULTI" => state.txn = TxnState::InMulti,
        "WATCH" => state.watch = WatchState::On,
        "UNWATCH" => state.watch = WatchState::Off,
        "EXEC" | "DISCARD" => {
            state.txn = TxnState::None;
            state.watch = WatchState::Off;
        }
        "CLIENT"
            if frame.args.first().is_some_and(|arg| arg == "TRACKING")
                && frame.args.get(1).is_some_and(|arg| arg == "ON") =>
        {
            state.tracking = TrackingState::On;
        }
        "CLIENT"
            if frame.args.first().is_some_and(|arg| arg == "TRACKING")
                && frame.args.get(1).is_some_and(|arg| arg == "OFF") =>
        {
            state.tracking = TrackingState::Off;
        }
        "RESET" => {
            *state = SessionState::default();
        }
        _ => {}
    }
}

pub fn is_error_response(response: &[u8]) -> bool {
    response.first().copied() == Some(b'-') || response.first().copied() == Some(b'!')
}

pub fn should_reauth_after_reset(frame: &FrameInfo, response: &[u8]) -> bool {
    frame.command == "RESET" && !is_error_response(response)
}

pub fn close_reason_from_io_error(err: &anyhow::Error) -> &'static str {
    let msg = err.to_string();
    if msg.contains("idle timeout") {
        "idle_timeout"
    } else if msg.contains("partial frame") {
        "partial_frame"
    } else if msg.contains("upstream closed") {
        "upstream_closed"
    } else {
        "error"
    }
}

pub fn parse_number(slice: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(slice).context("invalid number")?;
    let n = s.parse::<i64>().context("invalid number")?;
    Ok(n)
}

pub fn find_crlf(buf: &[u8]) -> Option<usize> {
    find_crlf_from(buf, 0)
}

pub fn find_crlf_from(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn to_upper_ascii_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_uppercase()
}

pub fn idle_timeout_from_secs(secs: u64) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(command: &str, args: &[&str]) -> FrameInfo {
        FrameInfo {
            len: 0,
            is_auth: false,
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }

    #[test]
    fn classify_tracking_on_pins_temporarily() {
        let frame = frame("CLIENT", &["TRACKING", "ON"]);
        assert_eq!(classify_command(&frame), CommandClass::PinTemporary);
    }

    #[test]
    fn classify_xread_block_pins_while_blocking() {
        let frame = frame("XREAD", &["BLOCK", "5000"]);
        assert_eq!(classify_command(&frame), CommandClass::PinWhileBlocking);
    }

    #[test]
    fn unpin_after_exec_clears_transaction_state() {
        let mut state = SessionState::default();
        let multi = frame("MULTI", &[]);
        let exec = frame("EXEC", &[]);

        apply_command_state_before_send(&mut state, &multi, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &multi,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &exec, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &exec,
            CommandClass::PinTemporary,
            b"*0\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn watch_then_unwatch_unpins() {
        let mut state = SessionState::default();
        let watch = frame("WATCH", &["key"]);
        let unwatch = frame("UNWATCH", &[]);

        apply_command_state_before_send(&mut state, &watch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &watch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &unwatch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &unwatch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn tracking_on_error_does_not_taint_state() {
        let mut state = SessionState::default();
        let tracking_on = frame("CLIENT", &["TRACKING", "ON"]);

        apply_command_state_before_send(&mut state, &tracking_on, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &tracking_on,
            CommandClass::PinTemporary,
            b"-ERR syntax error\r\n",
        );

        assert!(state.can_unpin());
    }

    #[test]
    fn blocking_state_clears_after_reply() {
        let mut state = SessionState::default();
        let blpop = frame("BLPOP", &["q", "10"]);

        apply_command_state_before_send(&mut state, &blpop, CommandClass::PinWhileBlocking);
        assert!(!state.can_unpin());

        apply_command_state_after_response(
            &mut state,
            &blpop,
            CommandClass::PinWhileBlocking,
            b"-ERR timeout\r\n",
        );
        assert!(state.can_unpin());
    }

    #[test]
    fn reset_clears_all_session_state() {
        let mut state = SessionState::default();
        let multi = frame("MULTI", &[]);
        let watch = frame("WATCH", &["k"]);
        let subscribe = frame("SUBSCRIBE", &["events"]);
        let blocking = frame("BLPOP", &["q", "10"]);
        let reset = frame("RESET", &[]);

        apply_command_state_before_send(&mut state, &multi, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &multi,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        apply_command_state_before_send(&mut state, &watch, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &watch,
            CommandClass::PinTemporary,
            b"+OK\r\n",
        );
        apply_command_state_before_send(&mut state, &subscribe, CommandClass::PinForever);
        apply_command_state_after_response(
            &mut state,
            &subscribe,
            CommandClass::PinForever,
            b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n",
        );
        apply_command_state_before_send(&mut state, &blocking, CommandClass::PinWhileBlocking);
        apply_command_state_after_response(
            &mut state,
            &blocking,
            CommandClass::PinWhileBlocking,
            b"$-1\r\n",
        );
        assert!(!state.can_unpin());

        apply_command_state_before_send(&mut state, &reset, CommandClass::PinTemporary);
        apply_command_state_after_response(
            &mut state,
            &reset,
            CommandClass::PinTemporary,
            b"+RESET\r\n",
        );

        assert!(state.can_unpin());
    }

    #[test]
    fn resp3_push_len_parses() {
        let frame = b">3\r\n+message\r\n$7\r\nchannel\r\n$5\r\nhello\r\n";
        let len = parse_resp_frame_len(frame)
            .expect("parse")
            .expect("complete frame");
        assert_eq!(len, frame.len());
    }

    #[test]
    fn resp3_map_len_parses() {
        let frame = b"%2\r\n+key1\r\n:1\r\n+key2\r\n$3\r\nval\r\n";
        let len = parse_resp_frame_len(frame)
            .expect("parse")
            .expect("complete frame");
        assert_eq!(len, frame.len());
    }

    #[test]
    fn reset_success_requires_reauth() {
        let reset = frame("RESET", &[]);
        assert!(should_reauth_after_reset(&reset, b"+RESET\r\n"));
    }

    #[test]
    fn reset_error_does_not_require_reauth() {
        let reset = frame("RESET", &[]);
        assert!(!should_reauth_after_reset(
            &reset,
            b"-ERR unknown command\r\n"
        ));
    }

    #[test]
    fn idle_timeout_zero_disables_timeout() {
        assert_eq!(idle_timeout_from_secs(0), None);
    }

    #[test]
    fn idle_timeout_positive_enables_timeout() {
        assert_eq!(
            idle_timeout_from_secs(300),
            Some(std::time::Duration::from_secs(300))
        );
    }
}

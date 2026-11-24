use super::*;

pub(super) struct InetSocket {
    pub(super) inode: u32,
    pub(super) uid: u32,
}

pub(super) struct PacketSocket {
    pub(super) inode: u32,
    pub(super) uid: u32,
    pub(super) has_filter: bool,
}

pub(super) struct NetlinkDiag {
    pub(super) fd: OwnedFd,
}

impl NetlinkDiag {
    pub(super) fn open() -> Result<Self, ViewError> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if raw < 0 {
            return Err(errno_to_view_error(last_errno()));
        }
        // SAFETY: `socket` returned a fresh owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let bind_result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
                core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            return Err(errno_to_view_error(last_errno()));
        }
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: NETLINK_RCV_TIMEOUT_US,
        };
        let set_result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast::<libc::c_void>(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if set_result < 0 {
            eprintln!(
                "cross-view netlink: SO_RCVTIMEO configuration failed ({}); dump may block",
                last_errno()
            );
        }
        Ok(Self { fd })
    }

    /// Sends one `SOCK_DIAG_BY_FAMILY` dump request and streams every parsed
    /// message into `on_message`. The request/response loop is bounded by
    /// [`NETLINK_MAX_BYTES`], [`NETLINK_MAX_MESSAGES`] and the receive timeout.
    pub(super) fn dump(
        &self,
        payload: &[u8],
        mut on_message: impl FnMut(&[u8]),
    ) -> Result<(), ViewError> {
        let mut request = vec![0u8; NLMSG_HDRLEN + payload.len()];
        let request_len = request.len() as u32;
        put_u32(&mut request, 0, request_len);
        put_u16(&mut request, 4, SOCK_DIAG_BY_FAMILY);
        put_u16(&mut request, 6, NLM_F_REQUEST | NLM_F_DUMP);
        put_u32(&mut request, 8, NETLINK_REQ_SEQ);
        put_u32(&mut request, 12, 0);
        request[NLMSG_HDRLEN..].copy_from_slice(payload);
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            return Err(errno_to_view_error(last_errno()));
        }
        if sent as usize != request.len() {
            return Err(ViewError::Failed);
        }

        let mut buffer = [0u8; NETLINK_RECV_BUF];
        let mut total_bytes = 0usize;
        let mut total_messages = 0usize;
        for _ in 0..1024 {
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                let errno = last_errno();
                if errno == libc::EINTR {
                    continue;
                }
                if errno == libc::EAGAIN {
                    return Err(ViewError::Failed);
                }
                return Err(errno_to_view_error(errno));
            }
            let received = received as usize;
            if received == 0 {
                return Err(ViewError::Failed);
            }
            total_bytes = total_bytes.saturating_add(received);
            if total_bytes > NETLINK_MAX_BYTES {
                return Err(ViewError::Failed);
            }
            let mut offset = 0usize;
            while offset + NLMSG_HDRLEN <= received {
                let Some(length) = read_u32(&buffer[..received], offset) else {
                    return Err(ViewError::Failed);
                };
                let length = length as usize;
                if length < NLMSG_HDRLEN || offset + length > received {
                    return Err(ViewError::Failed);
                }
                let Some(message_type) = read_u16(&buffer[..received], offset + 4) else {
                    return Err(ViewError::Failed);
                };
                let message = buffer
                    .get(offset..offset + length)
                    .ok_or(ViewError::Failed)?;
                total_messages += 1;
                if total_messages > NETLINK_MAX_MESSAGES {
                    return Err(ViewError::Failed);
                }
                match message_type {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        let error = read_i32(message, NLMSG_HDRLEN).unwrap_or(0);
                        if error != 0 {
                            return Err(errno_to_view_error(-error));
                        }
                    }
                    SOCK_DIAG_BY_FAMILY => {
                        if let Some(body) = message.get(NLMSG_HDRLEN..) {
                            on_message(body);
                        }
                    }
                    _ => {}
                }
                let aligned = nlmsg_align(length);
                if aligned == 0 {
                    return Err(ViewError::Failed);
                }
                offset = offset.saturating_add(aligned);
            }
        }
        Err(ViewError::Failed)
    }

    pub(super) fn dump_inet(&self, family: u8, protocol: u8) -> Result<Vec<InetSocket>, ViewError> {
        let mut request = [0u8; INET_DIAG_REQ_V2_BYTES];
        request[0] = family;
        request[1] = protocol;
        put_u32(&mut request, 4, u32::MAX); // idiag_states = all
        put_u32(&mut request, 48, u32::MAX); // idiag_cookie[0] = NOCOOKIE
        put_u32(&mut request, 52, u32::MAX); // idiag_cookie[1] = NOCOOKIE
        let mut sockets: Vec<InetSocket> = Vec::new();
        self.dump(&request, |body| {
            if sockets.len() >= CROSS_VIEW_MAX_BPF_OBJECTS {
                return;
            }
            if let Some(socket) = parse_inet_diag_msg(body) {
                sockets.push(socket);
            }
        })?;
        Ok(sockets)
    }

    pub(super) fn dump_packet(&self) -> Result<Vec<PacketSocket>, ViewError> {
        let mut request = [0u8; PACKET_DIAG_REQ_BYTES];
        request[0] = AF_PACKET_U8;
        put_u32(&mut request, 8, PACKET_SHOW_INFO | PACKET_SHOW_FILTER);
        put_u32(&mut request, 12, u32::MAX); // pdiag_cookie[0] = NOCOOKIE
        put_u32(&mut request, 16, u32::MAX); // pdiag_cookie[1] = NOCOOKIE
        let mut sockets: Vec<PacketSocket> = Vec::new();
        self.dump(&request, |body| {
            if sockets.len() >= CROSS_VIEW_MAX_BPF_OBJECTS {
                return;
            }
            if let Some(socket) = parse_packet_diag_msg(body) {
                sockets.push(socket);
            }
        })?;
        Ok(sockets)
    }
}

/// Decodes one `inet_diag_msg` (`struct inet_diag_msg`, 72 bytes; inode at 68,
/// uid at 64) from a netlink dump body. Zero inodes are not a socket identity and
/// are skipped.
pub(super) fn parse_inet_diag_msg(body: &[u8]) -> Option<InetSocket> {
    if body.len() < INET_DIAG_MSG_BYTES {
        return None;
    }
    let inode = read_u32(body, INET_DIAG_MSG_INODE_OFF)?;
    if inode == 0 {
        return None;
    }
    Some(InetSocket {
        inode,
        uid: read_u32(body, INET_DIAG_MSG_UID_OFF).unwrap_or(0),
    })
}

/// Decodes one `packet_diag_msg` (16-byte header + `nlattr` list) from a netlink
/// dump body. `PACKET_DIAG_UID` supplies the socket owner and any
/// `PACKET_DIAG_FILTER` attribute proves a tap filter is attached (BPFDoor's
/// classic-cBPF marker). Every attribute length is bounds-checked; a malformed
/// attribute ends the parse without inventing the remaining fields.
pub(super) fn parse_packet_diag_msg(body: &[u8]) -> Option<PacketSocket> {
    if body.len() < PACKET_DIAG_MSG_BYTES {
        return None;
    }
    let inode = read_u32(body, PACKET_DIAG_MSG_INODE_OFF)?;
    if inode == 0 {
        return None;
    }
    let mut uid = 0u32;
    let mut has_filter = false;
    let mut offset = PACKET_DIAG_MSG_BYTES;
    while offset + 4 <= body.len() {
        let Some(length) = read_u16(body, offset) else {
            break;
        };
        let Some(raw_type) = read_u16(body, offset + 2) else {
            break;
        };
        let length = length as usize;
        if length < 4 || offset.saturating_add(length) > body.len() {
            break;
        }
        match raw_type & 0x3fff {
            PACKET_DIAG_UID => {
                if let Some(value) =
                    read_u32(body.get(offset + 4..offset + length).unwrap_or(&[]), 0)
                {
                    uid = value;
                }
            }
            PACKET_DIAG_FILTER => has_filter = true,
            _ => {}
        }
        let aligned = nlmsg_align(length);
        if aligned == 0 {
            break;
        }
        offset = offset.saturating_add(aligned);
    }
    Some(PacketSocket {
        inode,
        uid,
        has_filter,
    })
}

pub(super) fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub(super) fn nlmsg_align(length: usize) -> usize {
    (length + 3) & !3
}

pub(super) fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    if let Some(slot) = buffer.get_mut(offset..offset.saturating_add(2)) {
        slot.copy_from_slice(&value.to_ne_bytes());
    }
}

pub(super) fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    if let Some(slot) = buffer.get_mut(offset..offset.saturating_add(4)) {
        slot.copy_from_slice(&value.to_ne_bytes());
    }
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slot = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_ne_bytes([slot[0], slot[1]]))
}

pub(super) fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let slot = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_ne_bytes([slot[0], slot[1], slot[2], slot[3]]))
}

// ===========================================================================
// procfs / sysfs readers
// ===========================================================================

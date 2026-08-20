"""
NetGuard - Netlink INET_DIAG Parser
Real parsing of Linux kernel socket notifications
"""

import struct
import socket
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

# Netlink message types
NLMSG_DONE = 3
NLMSG_ERROR = 2

# INET_DIAG constants
TCPDIAG_GETSOCK = 18
SOCK_DIAG_BY_FAMILY = 20
INET_DIAG_INFO = 2

# TCP states
TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}

@dataclass
class NetlinkSocket:
    """Parsed socket information from Netlink"""
    family: int          # AF_INET or AF_INET6
    state: int           # TCP state
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    uid: int
    inode: int
    protocol: str        # "TCP" or "UDP"
    
    def to_dict(self) -> Dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "uid": self.uid,
            "protocol": self.protocol,
            "state": TCP_STATES.get(self.state, "UNKNOWN"),
            "inode": self.inode,
            "tx_bytes": 0,
            "rx_bytes": 0,
        }


class NetlinkParser:
    """
    Parser for Netlink INET_DIAG messages.
    Extracts real socket information from kernel responses.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("NETLINK_PARSER")
    
    def parse_inet_diag_msg(self, data: bytes) -> Optional[NetlinkSocket]:
        """
        Parse a single inet_diag_msg structure.
        
        Structure (from linux/inet_diag.h):
        struct inet_diag_msg {
            __u8    idiag_family;
            __u8    idiag_state;
            __u8    idiag_timer;
            __u8    idiag_retrans;
            struct inet_diag_sockid id;
            __u32   idiag_expires;
            __u32   idiag_rqueue;
            __u32   idiag_wqueue;
            __u32   idiag_uid;
            __u32   idiag_inode;
        };
        
        struct inet_diag_sockid {
            __be16  idiag_sport;
            __be16  idiag_dport;
            __be32  idiag_src[4];
            __be32  idiag_dst[4];
            __u32   idiag_if;
            __u32   idiag_cookie[2];
        };
        """
        if len(data) < 72:  # Minimum size for inet_diag_msg
            return None
        
        try:
            # Parse header
            family, state, timer, retrans = struct.unpack("BBBB", data[0:4])
            
            # Parse sockid (starts at offset 4)
            src_port, dst_port = struct.unpack("!HH", data[4:8])
            
            if family == socket.AF_INET:
                # IPv4: only first 4 bytes of address arrays are used
                src_ip = socket.inet_ntoa(data[8:12])
                dst_ip = socket.inet_ntoa(data[24:28])
            elif family == socket.AF_INET6:
                # IPv6: all 16 bytes used
                src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
            else:
                return None
            
            # Header (4) + inet_diag_sockid (48), followed by five u32 fields.
            offset = 52
            expires, rqueue, wqueue, uid, inode = struct.unpack("IIIII", data[offset:offset+20])
            
            return NetlinkSocket(
                family=family,
                state=state,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                uid=uid,
                inode=inode,
                protocol="TCP"  # INET_DIAG is TCP-focused
            )
            
        except Exception as e:
            self.logger.debug(f"Parse error: {e}")
            return None
    
    def parse_netlink_response(self, data: bytes) -> List[NetlinkSocket]:
        """
        Parse a complete Netlink response containing multiple messages.
        
        Netlink message header:
        struct nlmsghdr {
            __u32 nlmsg_len;
            __u16 nlmsg_type;
            __u16 nlmsg_flags;
            __u32 nlmsg_seq;
            __u32 nlmsg_pid;
        };
        """
        sockets = []
        offset = 0
        
        while offset < len(data):
            if offset + 16 > len(data):
                break
            
            # Parse nlmsghdr
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack(
                "IHHII", data[offset:offset+16]
            )
            
            if nlmsg_len < 16 or nlmsg_len > len(data) - offset:
                break
            
            if nlmsg_type == NLMSG_DONE:
                break
            
            if nlmsg_type == NLMSG_ERROR:
                error_code = struct.unpack("i", data[offset+16:offset+20])[0]
                if error_code != 0:
                    self.logger.error(f"Netlink error: {error_code}")
                break
            
            # Parse inet_diag_msg (payload starts after nlmsghdr)
            payload_start = offset + 16
            payload_end = offset + nlmsg_len
            payload = data[payload_start:payload_end]
            
            sock = self.parse_inet_diag_msg(payload)
            if sock:
                sockets.append(sock)
            
            # Move to next message (aligned to 4 bytes)
            offset += (nlmsg_len + 3) & ~3
        
        return sockets
    
    def build_inet_diag_request(self, family: int = socket.AF_INET, 
                                 states: int = 0xFFF) -> bytes:
        """
        Build a Netlink request to dump all TCP sockets.
        
        struct inet_diag_req_v2 {
            __u8    sdiag_family;
            __u8    sdiag_protocol;
            __u8    idiag_ext;
            __u8    pad;
            __u32   idiag_states;
            struct inet_diag_sockid id;
        };
        """
        # Netlink header
        nlmsg_type = SOCK_DIAG_BY_FAMILY
        nlmsg_flags = 0x01 | 0x300  # NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH
        nlmsg_seq = 1
        nlmsg_pid = 0
        
        # inet_diag_req_v2
        sdiag_family = family
        sdiag_protocol = socket.IPPROTO_TCP
        idiag_ext = 0
        pad = 0
        idiag_states = states
        
        # Empty sockid (we want all sockets)
        sockid = b'\x00' * 48
        
        # Build request payload
        payload = struct.pack("BBBBI", sdiag_family, sdiag_protocol, idiag_ext, pad, idiag_states)
        payload += sockid
        
        # Build complete message
        nlmsg_len = 16 + len(payload)
        header = struct.pack("IHHII", nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)
        
        return header + payload


def parse_ss_output(output: str) -> List[Dict]:
    """
    Parse output from 'ss -ntup' command as fallback.
    
    Example output:
    Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
    tcp    ESTAB   0       0       192.168.1.5:52431   142.250.80.46:443  users:(("chrome",pid=1234,fd=45))
    """
    sockets = []
    lines = output.strip().split('\n')
    
    for line in lines[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        
        try:
            netid = parts[0]  # tcp, udp
            state = parts[1]
            local = parts[4]
            peer = parts[5]
            
            # Parse addresses
            local_ip, local_port = local.rsplit(':', 1)
            peer_ip, peer_port = peer.rsplit(':', 1)
            
            # Extract UID/PID from process info if available
            uid = 0
            if len(parts) > 6:
                proc_info = ' '.join(parts[6:])
                if 'pid=' in proc_info:
                    import re
                    match = re.search(r'pid=(\d+)', proc_info)
                    if match:
                        uid = int(match.group(1))
            
            sockets.append({
                "src_ip": local_ip.strip('[]'),
                "dst_ip": peer_ip.strip('[]'),
                "src_port": int(local_port),
                "dst_port": int(peer_port),
                "uid": uid,
                "protocol": netid.upper(),
                "state": state,
                "tx_bytes": 0,
                "rx_bytes": 0,
            })
        except (ValueError, IndexError) as e:
            continue
    
    return sockets

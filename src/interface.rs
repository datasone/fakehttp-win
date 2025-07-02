use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use itertools::Itertools;
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses,
        IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
};

pub struct Interface {
    index:         u32,
    friendly_name: String,
    description:   String,
    addrs:         Vec<IpAddr>,
}

impl Display for Interface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let display = format!(
            "Adapter (Interface Index {}):\n\tDescription: {}\n\tFriendly Name: {}\n\tAddresses: \
             [\n\t\t{}\n\t]",
            self.index,
            self.description,
            self.friendly_name,
            self.addrs.iter().join(",\n\t\t")
        );
        write!(f, "{}", display)
    }
}

pub fn query_interfaces() -> Result<Vec<Interface>, u32> {
    let mut size = 0u32;
    let err = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as _,
            GAA_FLAG_SKIP_UNICAST
                | GAA_FLAG_SKIP_ANYCAST
                | GAA_FLAG_SKIP_MULTICAST
                | GAA_FLAG_SKIP_DNS_SERVER
                | GAA_FLAG_INCLUDE_ALL_INTERFACES,
            None,
            None,
            &mut size,
        )
    };

    if err != ERROR_BUFFER_OVERFLOW.0 {
        return Err(err);
    };

    let mut buf = Vec::<u8>::with_capacity(size as _);
    let err = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as _,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
        )
    };
    if err != ERROR_SUCCESS.0 {
        return Err(err);
    }

    let mut interfaces = vec![];

    let addr_ref = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    if addr_ref.is_null() {
        return Ok(interfaces);
    }

    let mut addr_ref = unsafe { &(*addr_ref) };
    loop {
        let idx = unsafe { addr_ref.Anonymous1.Anonymous.IfIndex };
        let v6_idx = addr_ref.Ipv6IfIndex;
        let index = if idx != 0 { idx } else { v6_idx };

        let friendly_name = unsafe { String::from_utf16_lossy(addr_ref.FriendlyName.as_wide()) };
        let description = unsafe { String::from_utf16_lossy(addr_ref.Description.as_wide()) };

        let mut addrs = vec![];
        if !addr_ref.FirstUnicastAddress.is_null() {
            unsafe {
                let mut unicast_addr = &(*addr_ref.FirstUnicastAddress);
                loop {
                    let addr = unicast_addr.Address.lpSockaddr;
                    let family = (*addr).sa_family;
                    let addr = match family {
                        AF_INET => {
                            let addr = &(*(addr as *mut SOCKADDR_IN)).sin_addr;
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.S_un.S_addr)))
                        }
                        AF_INET6 => {
                            let addr = &(*(addr as *mut SOCKADDR_IN6)).sin6_addr;
                            IpAddr::V6(Ipv6Addr::from(addr.u.Byte))
                        }
                        _ => unreachable!(),
                    };
                    addrs.push(addr);
                    if unicast_addr.Next.is_null() {
                        break;
                    } else {
                        unicast_addr = &(*unicast_addr.Next);
                    }
                }
            }
        }

        let interface = Interface {
            index,
            friendly_name,
            description,
            addrs,
        };
        interfaces.push(interface);

        if addr_ref.Next.is_null() {
            break;
        } else {
            addr_ref = unsafe { &(*addr_ref.Next) };
        }
    }

    interfaces.sort_by_key(|interface| interface.index);
    Ok(interfaces)
}

//! The proxies whose word on a request's client address is taken: addresses and networks, written as a
//! comma-separated list (`10.0.0.5, 172.16.0.0/12, fd00::/8`). A client can write any forwarded header it likes, so
//! the header is believed only from a connection whose peer is on this list.

use std::net::IpAddr;

use crate::{Error, Result};

const FIELD: &str = "trusted_proxies";

/// One address family's network: the address with its host bits cleared and the prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    V4 { bits: u32, prefix: u32 },
    V6 { bits: u128, prefix: u32 },
}

/// The mask of a `prefix`-bit IPv4 network, or none for a prefix wider than the address.
fn mask4(prefix: u32) -> Option<u32> {
    let host = 32_u32.checked_sub(prefix)?;
    Some(u32::MAX.checked_shl(host).unwrap_or(0))
}

/// The mask of a `prefix`-bit IPv6 network, or none for a prefix wider than the address.
fn mask6(prefix: u32) -> Option<u128> {
    let host = 128_u32.checked_sub(prefix)?;
    Some(u128::MAX.checked_shl(host).unwrap_or(0))
}

impl Network {
    fn parse(entry: &str) -> Option<Self> {
        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (entry, None),
        };
        let address: IpAddr = address.parse().ok()?;
        // Digits only: `u32::from_str` would take a leading `+`.
        let prefix = match prefix {
            Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
                Some(text.parse::<u32>().ok()?)
            }
            Some(_) => return None,
            None => None,
        };
        match address {
            IpAddr::V4(address) => {
                let prefix = prefix.unwrap_or(32);
                let bits = u32::from(address) & mask4(prefix)?;
                Some(Self::V4 { bits, prefix })
            }
            IpAddr::V6(address) => {
                let prefix = prefix.unwrap_or(128);
                let bits = u128::from(address) & mask6(prefix)?;
                Some(Self::V6 { bits, prefix })
            }
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { bits, prefix }, IpAddr::V4(address)) => {
                mask4(prefix).is_some_and(|mask| u32::from(address) & mask == bits)
            }
            (Self::V6 { bits, prefix }, IpAddr::V6(address)) => {
                mask6(prefix).is_some_and(|mask| u128::from(address) & mask == bits)
            }
            _ => false,
        }
    }
}

/// Addresses and networks of the proxies in front of the server; empty trusts nobody.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    networks: Vec<Network>,
}

impl TrustedProxies {
    /// The comma-separated list `text`, each entry an address or `address/prefix`; empty is the empty list.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] on `trusted_proxies` when an entry is neither.
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        let networks = text
            .split(',')
            .map(|entry| {
                Network::parse(entry.trim()).ok_or(Error::Invalid {
                    field: FIELD,
                    reason: "each entry must be an IP address or an address/prefix network",
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { networks })
    }

    /// Whether `address` is one of the proxies; an IPv4-mapped IPv6 address is read as its IPv4 address.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
            IpAddr::V4(_) => address,
        };
        self.networks
            .iter()
            .any(|network| network.contains(address))
    }

    /// Whether no proxy is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

#[cfg(test)]
#[path = "trusted_proxies_tests.rs"]
mod tests;

use std::future::{AsyncDrop, Future};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use futures_util::TryStreamExt;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteScope, RouteType,
};
use netlink_packet_route::rule::{RuleAttribute, RuleHeader, RuleMessage};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, IpVersion};
use share::route::FWMARK;
use tokio::task::JoinHandle;
use tracing::{error, info};

const TABLE: u32 = 2022;
const LO_IFACE_INDEX: u32 = 1;

#[derive(Debug)]
pub struct RouteRuleGuard {
    connection_task: JoinHandle<()>,
    handle: Handle,
}

impl AsyncDrop for RouteRuleGuard {
    type Dropper<'a> = impl Future<Output=()> where Self: 'a;

    fn async_drop(self: Pin<&mut Self>) -> Self::Dropper<'_> {
        async move {
            for (af, ip) in [
                (
                    AddressFamily::Inet,
                    RouteAddress::Inet(Ipv4Addr::UNSPECIFIED),
                ),
                (
                    AddressFamily::Inet6,
                    RouteAddress::Inet6(Ipv6Addr::UNSPECIFIED),
                ),
            ] {
                let mut route_message = RouteMessage::default();
                route_message.header = RouteHeader {
                    address_family: af,
                    destination_prefix_length: 0,
                    scope: RouteScope::Host,
                    kind: RouteType::Local,
                    ..Default::default()
                };
                route_message.attributes = vec![
                    RouteAttribute::Table(TABLE),
                    RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::UNSPECIFIED)),
                    RouteAttribute::Oif(LO_IFACE_INDEX),
                ];

                if let Err(err) = self.handle.route().del(route_message).execute().await {
                    error!(?af, ?ip, %err, "delete route rule failed");
                }

                let mut rule_message = RuleMessage::default();
                rule_message.header = RuleHeader {
                    family: af,
                    ..Default::default()
                };
                rule_message.attributes =
                    vec![RuleAttribute::Table(TABLE), RuleAttribute::FwMark(FWMARK)];

                if let Err(err) = self.handle.rule().del(rule_message).execute().await {
                    error!(?af, %err, "delete policy rule failed");
                }
            }

            self.connection_task.abort();
        }
    }
}

pub async fn enable_container_route() -> anyhow::Result<RouteRuleGuard> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    let task = tokio::spawn(conn);

    add_route_rule(&handle).await?;

    Ok(RouteRuleGuard {
        connection_task: task,
        handle,
    })
}

async fn add_route_rule(handle: &Handle) -> anyhow::Result<()> {
    // policy rule check
    let (ipv4_exist, ipv6_exist) = check_rule_exist(handle).await?;
    if !ipv4_exist {
        handle
            .rule()
            .add()
            .fw_mark(FWMARK)
            .table_id(TABLE)
            .v4()
            .execute()
            .await?;

        info!("add ipv4 policy rule done");
    }
    if !ipv6_exist {
        handle
            .rule()
            .add()
            .fw_mark(FWMARK)
            .table_id(TABLE)
            .v6()
            .execute()
            .await?;

        info!("add ipv6 policy rule done");
    }

    // route check
    let (ipv4_exist, ipv6_exist) = check_route_exist(handle).await?;
    if !ipv4_exist {
        // ip r add local default dev lo table TABLE
        handle
            .route()
            .add()
            .v4()
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .output_interface(LO_IFACE_INDEX)
            .table_id(TABLE)
            .execute()
            .await?;

        info!("add ipv4 route rule done");
    }
    if !ipv6_exist {
        // ip -6 r add local default dev lo table TABLE
        handle
            .route()
            .add()
            .v6()
            .kind(RouteType::Local)
            .scope(RouteScope::Host)
            .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
            .output_interface(LO_IFACE_INDEX)
            .table_id(TABLE)
            .execute()
            .await?;

        info!("add ipv6 route rule done");
    }

    Ok(())
}

async fn check_route_exist(handle: &Handle) -> anyhow::Result<(bool, bool)> {
    let ipv4_exist = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_any(route_filter)
        .await?;
    let ipv6_exist = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_any(route_filter)
        .await?;

    Ok((ipv4_exist, ipv6_exist))
}

async fn route_filter(route: RouteMessage) -> bool {
    route.attributes.contains(&RouteAttribute::Table(TABLE))
        && route
            .attributes
            .contains(&RouteAttribute::Oif(LO_IFACE_INDEX))
        && route.header.destination_prefix_length == 0
        && route.header.source_prefix_length == 0
        && route.header.scope == RouteScope::Host
        && route.header.kind == RouteType::Local
}

async fn check_rule_exist(handle: &Handle) -> anyhow::Result<(bool, bool)> {
    let ipv4_st = handle.rule().get(IpVersion::V4).execute();
    let ipv4_exist = ipv4_st.try_any(rule_filter).await?;

    let ipv6_st = handle.rule().get(IpVersion::V6).execute();
    let ipv6_exist = ipv6_st.try_any(rule_filter).await?;

    Ok((ipv4_exist, ipv6_exist))
}

async fn rule_filter(rule: RuleMessage) -> bool {
    rule.attributes.contains(&RuleAttribute::Table(TABLE))
        && rule.attributes.contains(&RuleAttribute::FwMark(FWMARK))
}

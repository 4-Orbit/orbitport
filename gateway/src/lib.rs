// Include the `items` module, which is generated from items.proto.
// It is important to maintain the same structure as in the proto.
// generated code: clippy 1.99 flags tonic's async_trait servers with double_must_use
#[allow(clippy::double_must_use)]
pub mod proto {
    pub mod plugins {
        pub mod account {
            tonic::include_proto!("account");
        }
        pub mod auth {
            tonic::include_proto!("auth");
        }
        pub mod ao {
            tonic::include_proto!("ao");
        }
        pub mod ipfs {
            tonic::include_proto!("ipfs");
        }
        pub mod patissuer {
            tonic::include_proto!("patissuer");
        }
        pub mod kms {
            tonic::include_proto!("kmsapi");
        }
        pub mod masterseed {
            tonic::include_proto!("masterseed");
        }
        pub mod threshold {
            tonic::include_proto!("thresholdapi");
        }
        pub mod policy {
            tonic::include_proto!("policy");
        }
    }

    pub mod services {
        pub mod ctrng {
            tonic::include_proto!("ctrng");
        }
        pub mod kms {
            pub use orbitport_kms_api::kms::*;
        }
        pub mod threshold {
            tonic::include_proto!("threshold");
        }
    }
}

pub mod types;

pub mod logging;
pub mod metrics;

pub mod agent_delegation;
pub mod agent_request_auth;
pub mod auth;
pub mod caller;
pub mod filters;
pub mod plugins;
pub mod server;
pub mod service_manager;
pub mod services;
pub mod structures;
pub mod trng;

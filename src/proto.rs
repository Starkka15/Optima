//! prost-generated types from the reverse-engineered Ubisoft Connect protobufs
//! (proto/demux.proto, proto/ownership.proto — sourced from YoobieRE's work).
//! Package `mg.protocol.demux` / `mg.protocol.ownership`.

pub mod demux {
    include!(concat!(env!("OUT_DIR"), "/mg.protocol.demux.rs"));
}

pub mod ownership {
    include!(concat!(env!("OUT_DIR"), "/mg.protocol.ownership.rs"));
}

pub mod download {
    include!(concat!(env!("OUT_DIR"), "/mg.protocol.download.rs"));
}

pub mod download_service {
    include!(concat!(env!("OUT_DIR"), "/mg.protocol.download_service.rs"));
}

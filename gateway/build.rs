use std::io::Result;

const SERDE_DERIVES: &str = "#[derive(serde::Serialize, serde::Deserialize)]";
const PASCAL_CASE: &str = "#[serde(rename_all = \"PascalCase\")]";
const THRESHOLD_PASCAL_CASE_TYPES: &[&str] = &["threshold.DkgRequest", "threshold.DkgResponse"];

fn apply_service_attributes(config: tonic_prost_build::Builder) -> tonic_prost_build::Builder {
    THRESHOLD_PASCAL_CASE_TYPES
        .iter()
        .fold(config, |config, ty| config.type_attribute(*ty, PASCAL_CASE))
}

fn build_plugins(proto_dir: &str) -> Result<()> {
    let (_, plugin_protos) = protos_in_dir(proto_dir)?;

    // Enable server stubs only for protos that need to be mocked in
    // gateway-side integration tests. Today: account.
    tonic_prost_build::configure()
        .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &plugin_protos.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &[proto_dir],
        )?;

    Ok(())
}

fn build_services(proto_dir: &str) -> Result<()> {
    let (_, service_protos) = protos_in_dir(proto_dir)?;

    let config = apply_service_attributes(
        tonic_prost_build::configure()
            .build_server(false)
            .protoc_arg("--experimental_allow_proto3_optional")
            // Add serde attributes to all generated message structs.
            .type_attribute(".", SERDE_DERIVES),
    );

    config.compile_protos(
        &service_protos
            .iter()
            // Public KMS types are generated once in orbitport-kms-api.
            .filter(|s| !s.ends_with("/kms.proto"))
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        &[proto_dir],
    )?;

    Ok(())
}

fn main() -> Result<()> {
    if let Err(_e) = build_plugins("../proto/plugins") {
        build_plugins("./proto/plugins")?;
    }

    if let Err(_e) = build_services("../proto/services") {
        build_services("./proto/services")?;
    }

    Ok(())
}

fn protos_in_dir(dir: &str) -> Result<(String, Vec<String>)> {
    if !std::path::Path::new(dir).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Directory {dir} not found"),
        ));
    }

    let mut protos = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let (_, mut nested_protos) = protos_in_dir(entry.path().to_str().unwrap())?;
            protos.append(&mut nested_protos);
            continue;
        }

        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("proto") {
            protos.push(path.to_str().unwrap().to_string());
        }
    }

    Ok((dir.to_string(), protos))
}

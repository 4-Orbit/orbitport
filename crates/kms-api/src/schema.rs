//! Schema constraints come from the same capabilities used by the gateway.
use crate::KmsValidation;
use schemars::{Schema, SchemaGenerator};
use serde_json::{Value, json};

fn choices(values: impl IntoIterator<Item = String>, nullable: bool) -> Schema {
    let mut values: Vec<Value> = values.into_iter().map(Value::String).collect();
    values.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    values.dedup();
    if nullable {
        values.push(Value::Null);
    }
    let kind = if nullable {
        json!(["string", "null"])
    } else {
        json!("string")
    };
    Schema::try_from(json!({"type":kind,"enum":values})).expect("static schema")
}

pub fn key_spec(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.key_specs),
        false,
    )
}

pub fn positive_u32(_: &mut SchemaGenerator) -> Schema {
    Schema::try_from(json!({
        "type": ["integer", "null"], "minimum": 1, "maximum": u32::MAX
    }))
    .expect("static schema")
}

pub fn key_usage(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.key_usages),
        false,
    )
}

pub fn scheme(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .map(|s| s.scheme)
            .chain([String::new()]),
        true,
    )
}

pub fn signing_algorithm(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.signing_capabilities)
            .map(|s| s.signing_algorithm),
        false,
    )
}

pub fn message_type(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.signing_capabilities)
            .flat_map(|s| s.message_types),
        true,
    )
}

pub fn encryption_algorithm(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.encryption_algorithms),
        true,
    )
}

pub fn data_key_spec(_: &mut SchemaGenerator) -> Schema {
    choices(
        KmsValidation::get_capabilities()
            .schemes
            .into_iter()
            .flat_map(|s| s.data_key_specs),
        true,
    )
}

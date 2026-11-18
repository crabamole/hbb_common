include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

#[cfg(test)]
mod tests {
    use super::rendezvous::*;
    use protobuf::{CodedInputStream, Enum, Message};

    fn tags(msg: &impl Message) -> Vec<u32> {
        let bytes = msg.write_to_bytes().unwrap();
        let mut is = CodedInputStream::from_bytes(&bytes);
        let mut tags = vec![];
        while let Some(tag) = is.read_raw_tag_or_eof().unwrap() {
            tags.push(tag >> 3);
            is.skip_field(protobuf::rt::WireType::new(tag & 7).unwrap()).unwrap();
        }
        tags
    }

    #[test]
    fn controlled_context_uses_our_field_numbers() {
        let ctx = ControlledContext {
            same_user: true,
            owner_pk: vec![1].into(),
            ..Default::default()
        };
        assert_eq!(tags(&ctx), vec![1001, 1002]);
    }

    #[test]
    fn key_change_refused_uses_our_value() {
        assert_eq!(register_pk_response::Result::KEY_CHANGE_REFUSED.value(), 1001);
    }
}

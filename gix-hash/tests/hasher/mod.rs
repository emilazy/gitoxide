use gix_hash::Hasher;

#[test]
fn size_of_sha1() {
    assert_eq!(std::mem::size_of::<Hasher>(), 2392);
}

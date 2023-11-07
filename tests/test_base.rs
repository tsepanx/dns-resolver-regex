use proj2::my_bytes::Bytes2;
use rand::prelude::*;

fn bidirectional_convert<T>(v_from: &Vec<T>) -> Vec<T>
where
    T: Clone,
{
    let bytes_view = Bytes2::from((*v_from).clone());
    let v_to = Bytes2::into(bytes_view);
    v_to
}

#[test]
fn test_v_i32() {
    let mut rng = thread_rng();

    for i in 1..101 {
        println!("=== {:} ===", i);
        let len = rng.gen_range(0..200);
        let v_from: Vec<i32> = (0..len).map(|_| rng.gen()).collect();

        let v_to = bidirectional_convert::<i32>(&v_from);
        assert_eq!(v_from, v_to);
    }
}

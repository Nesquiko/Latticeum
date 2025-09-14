#![no_main]
#![no_std]

guest::guest_main!(main);

fn main() {
    let n = 100;
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    let mut sum: u32;
    for _ in 1..n {
        sum = a.wrapping_add(b);
        a = b;
        b = sum;
    }

    guest::write_result(b);
}

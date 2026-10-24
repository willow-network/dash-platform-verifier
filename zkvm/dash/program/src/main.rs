#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: dash_lane_core::Input = sp1_zkvm::io::read();
    let statement = dash_lane_core::verify(&input).expect("dash username statement rejected");
    sp1_zkvm::io::commit_slice(&dash_lane_core::public_values(&statement));
}

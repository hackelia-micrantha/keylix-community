//! Deterministically validate and execute bounded AI adversarial candidates.

use std::io::{self, Read};

use keylix_conformance::ai_adversary::CandidateBatch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let batch = CandidateBatch::parse_canonical(&input)?;
    for result in batch.evaluate()? {
        println!(
            "{}\t{:?}\t{:?}\t{}",
            result.id,
            result.mutation,
            result.observed,
            if result.novel_dimension {
                "novel-dimension"
            } else {
                "covered-dimension"
            }
        );
    }
    Ok(())
}

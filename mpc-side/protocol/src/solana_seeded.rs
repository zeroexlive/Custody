//! Standard Solana wire verification primitives only. These do not attest a FROST
//! origin, issue an account or authorize signing. Enrollment and original intent
//! must be independently authenticated before this verifier is connected.
use anyhow::{ensure, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

type Key = [u8; 32];
const SYSTEM: Key = [0; 32];
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

pub fn key(value: &str) -> Result<Key> {
    ensure!((32..=44).contains(&value.len()), "public key text bounds");
    let bytes = bs58::decode(value).into_vec()?;
    let key: Key = bytes.try_into().map_err(|_| anyhow::anyhow!("key width"))?;
    ensure!(bs58::encode(key).into_string() == value, "noncanonical key");
    Ok(key)
}
pub fn seed(index: u64, token: bool) -> Result<String> {
    ensure!(index <= i64::MAX as u64, "unallocated seed index");
    Ok(format!("c1{}{index:029x}", if token { 't' } else { 'n' }))
}
pub fn address(base: &Key, index: u64, token: bool) -> Result<Key> {
    ensure!(
        *base != SYSTEM && CompressedEdwardsY(*base).decompress().is_some(),
        "base shape"
    );
    let owner = if token { key(TOKEN)? } else { SYSTEM };
    Ok(Sha256::digest([base.as_slice(), seed(index, token)?.as_bytes(), &owner].concat()).into())
}
pub fn associated_address(owner: &Key, mint: &Key) -> Result<Key> {
    let token = key(TOKEN)?;
    let program = key(ATA)?;
    for bump in (0u8..=255).rev() {
        let digest: Key = Sha256::digest(
            [
                owner.as_slice(),
                &token,
                mint,
                &[bump],
                &program,
                b"ProgramDerivedAddress",
            ]
            .concat(),
        )
        .into();
        if CompressedEdwardsY(digest).decompress().is_none() {
            return Ok(digest);
        }
    }
    anyhow::bail!("no associated account PDA")
}
#[derive(Clone, Debug)]
pub enum Operation {
    Native {
        destination: Key,
        amount: u64,
    },
    CreateToken {
        mint: Key,
        rent: u64,
    },
    Token {
        mint: Key,
        destination_owner: Key,
        amount: u64,
        decimals: u8,
        create_ata: bool,
    },
}
#[derive(Debug)]
struct Instruction {
    program: Key,
    accounts: Vec<(Key, bool, bool)>,
    data: Vec<u8>,
}
fn expected(base: Key, index: u64, op: &Operation) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let token = key(TOKEN)?;
    match op {
        Operation::Native {
            destination,
            amount,
        } => {
            ensure!(*amount > 0, "zero amount");
            let source = address(&base, index, false)?;
            ensure!(source != *destination, "same source and destination");
            let seed = seed(index, false)?;
            let data = [
                11u32.to_le_bytes().as_slice(),
                &amount.to_le_bytes(),
                &(seed.len() as u64).to_le_bytes(),
                seed.as_bytes(),
                &SYSTEM,
            ]
            .concat();
            out.push(Instruction {
                program: SYSTEM,
                accounts: vec![
                    (source, false, true),
                    (base, true, false),
                    (*destination, false, true),
                ],
                data,
            });
        }
        Operation::CreateToken { mint, rent } => {
            ensure!(*rent > 0, "zero rent");
            let source = address(&base, index, true)?;
            let seed = seed(index, true)?;
            let data = [
                3u32.to_le_bytes().as_slice(),
                &base,
                &(seed.len() as u64).to_le_bytes(),
                seed.as_bytes(),
                &rent.to_le_bytes(),
                &165u64.to_le_bytes(),
                &token,
            ]
            .concat();
            out.push(Instruction {
                program: SYSTEM,
                accounts: vec![(base, true, true), (source, false, true)],
                data,
            });
            out.push(Instruction {
                program: token,
                accounts: vec![(source, false, true), (*mint, false, false)],
                data: [&[18], base.as_slice()].concat(),
            });
        }
        Operation::Token {
            mint,
            destination_owner,
            amount,
            decimals,
            create_ata,
        } => {
            ensure!(*amount > 0 && *decimals <= 18, "token amount/precision");
            let source = address(&base, index, true)?;
            let target = associated_address(destination_owner, mint)?;
            ensure!(source != target, "same token source and destination");
            if *create_ata {
                out.push(Instruction {
                    program: key(ATA)?,
                    accounts: vec![
                        (base, true, true),
                        (target, false, true),
                        (*destination_owner, false, false),
                        (*mint, false, false),
                        (SYSTEM, false, false),
                        (token, false, false),
                    ],
                    data: vec![1],
                });
            }
            out.push(Instruction {
                program: token,
                accounts: vec![
                    (source, false, true),
                    (*mint, false, false),
                    (target, false, true),
                    (base, true, false),
                ],
                data: [&[12], amount.to_le_bytes().as_slice(), &[*decimals]].concat(),
            });
        }
    }
    Ok(out)
}
fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    ensure!(input.len() >= len, "truncated message");
    let (part, rest) = input.split_at(len);
    *input = rest;
    Ok(part)
}
fn short(input: &mut &[u8]) -> Result<usize> {
    let mut n = 0usize;
    for i in 0..3 {
        let b = take(input, 1)?[0];
        ensure!(i < 2 || b <= 3, "shortvec overflow");
        ensure!(i == 0 || b != 0, "noncanonical shortvec");
        n |= usize::from(b & 127) << (7 * i);
        if b & 128 == 0 {
            return Ok(n);
        }
    }
    anyhow::bail!("overlong shortvec")
}
/// Validate exact typed instruction semantics, complete account set/flags, fee
/// authority and blockhash. This cannot authenticate the caller-supplied intent.
pub fn validate(raw: &[u8], base: Key, index: u64, blockhash: Key, op: &Operation) -> Result<()> {
    ensure!(!raw.is_empty() && raw.len() + 65 <= 1232, "message bounds");
    let instructions = expected(base, index, op)?;
    let mut required = BTreeMap::<Key, (bool, bool)>::new();
    required.insert(base, (true, true));
    for ins in &instructions {
        required.entry(ins.program).or_default();
        for (key, s, w) in &ins.accounts {
            let flags = required.entry(*key).or_default();
            flags.0 |= *s;
            flags.1 |= *w;
        }
    }
    let mut cursor = raw;
    let header = take(&mut cursor, 3)?;
    ensure!(
        header[0] == 1 && header[1] == 0,
        "single writable FROST signer required"
    );
    let count = short(&mut cursor)?;
    ensure!(
        (1..=256).contains(&count) && usize::from(header[2]) < count,
        "account bounds"
    );
    ensure!(count == required.len(), "extraneous or missing accounts");
    let writable_end = count - usize::from(header[2]);
    let mut keys = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    for i in 0..count {
        let k: Key = take(&mut cursor, 32)?.try_into()?;
        ensure!(seen.insert(k), "duplicate key");
        ensure!(
            required.get(&k) == Some(&(i == 0, i < writable_end)),
            "wrong account flags"
        );
        keys.push(k);
    }
    ensure!(keys[0] == base, "wrong fee/signing authority");
    // Match the SDK's deterministic legacy compilation order: fee payer, then
    // unsigned writable and unsigned readonly keys, each ordered by key bytes.
    // A coordinated key-table/index permutation is semantically equivalent but
    // differs from the one original canonical message approved by custody.
    let mut ordered: Vec<_> = required.iter().filter(|(key, _)| **key != base).collect();
    ordered.sort_by_key(|(key, flags)| (!flags.1, **key));
    let canonical: Vec<_> = core::iter::once(base)
        .chain(ordered.into_iter().map(|(key, _)| *key))
        .collect();
    ensure!(keys == canonical, "noncanonical SDK account ordering");
    ensure!(take(&mut cursor, 32)? == blockhash, "blockhash mismatch");
    ensure!(
        short(&mut cursor)? == instructions.len(),
        "extra or missing instructions"
    );
    for expected in instructions {
        let program = usize::from(take(&mut cursor, 1)?[0]);
        ensure!(
            keys.get(program) == Some(&expected.program),
            "program mismatch"
        );
        ensure!(
            short(&mut cursor)? == expected.accounts.len(),
            "instruction account count"
        );
        for (k, _, _) in expected.accounts {
            let i = usize::from(take(&mut cursor, 1)?[0]);
            ensure!(keys.get(i) == Some(&k), "instruction account mismatch");
        }
        let len = short(&mut cursor)?;
        ensure!(
            take(&mut cursor, len)? == expected.data,
            "instruction payload mismatch"
        );
    }
    ensure!(cursor.is_empty(), "trailing message bytes");
    Ok(())
}

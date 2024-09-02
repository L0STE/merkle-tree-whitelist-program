import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SimpleMerkleWhitelist } from "../target/types/simple_merkle_whitelist";
import { expect } from "chai";
import { Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL, Transaction } from "@solana/web3.js";
import { HashingAlgorithm, MerkleTree } from "svm-merkle-tree";

describe("simple-merkle-whitelist", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const wallet = anchor.Wallet.local();

  const program = anchor.workspace.SimpleMerkleWhitelist as Program<SimpleMerkleWhitelist>;

  let whitelistState: PublicKey;
  let authority: Keypair;
  let merkleTree: MerkleTree;
  let whitelistedAddresses: PublicKey[];

  before(async () => {
    whitelistState = PublicKey.findProgramAddressSync([Buffer.from("whitelist")], program.programId)[0];
    authority = wallet.payer;

    // Airdrop SOL to authority
    await provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: provider.publicKey,
          toPubkey: authority.publicKey,
          lamports: 10 * LAMPORTS_PER_SOL,
        })
      ), 
      []
    );

    // Generate 100 random addresses
    whitelistedAddresses = Array.from({ length: 100 }, () => Keypair.generate().publicKey);

    // Create Merkle Tree
    merkleTree = new MerkleTree(HashingAlgorithm.Keccak, 32);
    whitelistedAddresses.forEach((address) => {
      merkleTree.add_leaf(address.toBytes());
    });
    merkleTree.merklize();
  });

  xit("Initialize whitelist", async () => {
    const merkleRoot = Array.from(merkleTree.get_merkle_root());

    await program.methods.initialize(merkleRoot)
      .accountsPartial({
        whitelistState: whitelistState,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    const account = await program.account.whitelistState.fetch(whitelistState);
    expect(account.merkleRoot).to.deep.equal(merkleRoot);
    expect(account.authority.toString()).to.equal(authority.publicKey.toString());
  });

  it("Update root", async () => {
    const newAddress = Keypair.generate().publicKey;
    whitelistedAddresses.push(newAddress); 
    merkleTree.add_leaf(newAddress.toBytes());
    merkleTree.merklize();

    const newMerkleRoot = Array.from(merkleTree.get_merkle_root());

    await program.methods.updateRoot(newMerkleRoot)
      .accountsPartial({
        whitelistState: whitelistState,
        authority: authority.publicKey,
      })
      .signers([authority])
      .rpc();

    const account = await program.account.whitelistState.fetch(whitelistState);
    expect(account.merkleRoot).to.deep.equal(newMerkleRoot);
  });

  it("Perform action with whitelisted address", async () => {
    const newAddress = Keypair.generate();
    whitelistedAddresses.push(newAddress.publicKey); 
    merkleTree.add_leaf(newAddress.publicKey.toBytes());
    merkleTree.merklize();
  
    const newMerkleRoot = Array.from(merkleTree.get_merkle_root());
  
    await program.methods.updateRoot(newMerkleRoot)
      .accountsPartial({
        whitelistState: whitelistState,
        authority: authority.publicKey,
      })
      .signers([authority])
      .rpc();
  
    const index = whitelistedAddresses.findIndex(addr => addr.equals(newAddress.publicKey));
    
    const proof = merkleTree.merkle_proof_index(index);
    const proofArray = Buffer.from(proof.get_pairing_hashes());
  
    try {
      await program.methods.action(proofArray, new anchor.BN(index))
        .accountsPartial({
          signer: newAddress.publicKey,
          whitelistState,
        })
        .signers([newAddress])
        .rpc();
      console.log("Action performed successfully for whitelisted address");
    } catch (error) {
      console.error("Error performing action:", error);
      throw error;
    }
  });

  it("Fail action with non-whitelisted address", async () => {
    const nonWhitelistedKeypair = Keypair.generate();
    const whitelistedKeypair = whitelistedAddresses[0];
    const whitelistedAddress = whitelistedKeypair;
  
    // Find the index of the whitelisted address
    const index = whitelistedAddresses.findIndex(addr => addr.equals(whitelistedAddress));
    
    if (index === -1) {
      throw new Error("Whitelisted address not found");
    }
  
    // Generate the Merkle proof for the whitelisted address
    const proof = merkleTree.merkle_proof_index(index);
    const proofArray = Buffer.from(proof.get_pairing_hashes());
  
    try {
      // Try to use the proof of a whitelisted address with a non-whitelisted address
      await program.methods.action(proofArray, new anchor.BN(index))
        .accountsPartial({
          signer: nonWhitelistedKeypair.publicKey,
          whitelistState: whitelistState,
        })
        .signers([nonWhitelistedKeypair])
        .rpc();
      
      expect.fail("Action should have failed for non-whitelisted address");
    } catch (error: any) {
      expect(error.error.errorMessage).to.equal("Invalid Merkle proof");
    }
  });

  it("Fail to update root with non-authority signer", async () => {
    const newMerkleRoot = Array.from(merkleTree.get_merkle_root());
    const nonAuthority = Keypair.generate();

    try {
      await program.methods.updateRoot(newMerkleRoot)
        .accountsPartial({
          whitelistState: whitelistState,
          authority: nonAuthority.publicKey,
        })
        .signers([nonAuthority])
        .rpc();
      
      expect.fail("Update should have failed for non-authority signer");
    } catch (error: any) {
      expect(error.error.errorMessage).to.equal("A has one constraint was violated");
    }
  });
});
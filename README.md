---
eip: <to be assigned>
title: HNFT – Human Non-Fungible Token Standard
description: A standard for representing human identity and behavior data as non-fungible tokens with zero-knowledge proof support, encrypted metadata, and account abstraction integration.
author: Gerrry Alvrz (@brahma101.eth)
discussions-to: https://ethereum-magicians.org/t/eip-hnft-human-non-fungible-token-standard/12345
status: Draft
type: Standards Track
category: ERC
created: 2025-07-27
requires: EIP-165, EIP-721, EIP-2981 (optional), EIP-4337 (optional)
---

## Table of Contents
- [Simple Summary](#simple-summary)
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Specification](#specification)
- [Caveats](#caveats)
- [Rationale](#rationale)
- [Backwards Compatibility](#backwards-compatibility)
- [Test Cases](#test-cases)
- [Implementations](#implementations)
- [Security Considerations](#security-considerations)
- [References](#references)
- [Copyright](#copyright)

## Simple Summary
A standard interface for Human Non-Fungible Tokens (HNFTs), extending ERC-721 to encapsulate verifiable human identity and behavior data with zero-knowledge proofs, encrypted metadata, modular governance, and optional account abstraction for user-friendly key management and transaction flexibility.

## Abstract
The HNFT standard extends ERC-721 to create a programmable, cryptographically secure identity container for human subjects or digital personas. It introduces:

- **Trait-based verifiable claims** using a `traitId` system for dynamic identity attributes.
- **Encrypted metadata** layers to protect sensitive data.
- **Zero-knowledge proof (ZKP)** support for privacy-preserving trait validation.
- **Optional governance** for trait verification and slashing.
- **Quantum-resilient cryptography** for long-term security.
- **Account abstraction** integration via EIP-4337 for gasless transactions and flexible authorization.
- **Hybrid onchain-offchain integration** for scalability and interoperability with decentralized identifiers (DIDs) and verifiable credentials (VCs).

HNFTs enable self-sovereign identity, machine-verifiable trust scores, and behavioral ledgers while preserving privacy. They are designed for applications like decentralized AI, social protocols, and reputation systems, with enhanced usability through account abstraction.

## Motivation
Web3 lacks a standardized, privacy-preserving mechanism for encoding human identity. Existing NFT standards (ERC-721, ERC-1155) are insufficient for identity use cases due to:

- Lack of dynamic, verifiable trait systems.
- No support for encrypted or private metadata.
- Inability to prove traits without revealing sensitive data.
- Limited interoperability with DID and VC standards.
- Vulnerability to centralized metadata storage.
- Complex user experience for key management and transaction signing.

HNFTs address these gaps by providing:

- A **modular identity container** compatible with zero-knowledge systems and L2 rollups.
- **Privacy-preserving verification** for pseudonymous traits and credentials.
- **Governance hooks** for decentralized trust and accountability.
- **Interoperability** with DID, VC, and Web3 ecosystems.
- **Account abstraction** for simplified key management, gasless interactions, and programmable authorization.

Applications include decentralized AI governance, post-platform social networks, behavioral staking, and privacy-preserving reputation systems.

## Specification
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

Every HNFT-compliant contract MUST implement the `IHNFT` interface, which extends `ERC721`, `ERC165`, and optionally `ERC721Metadata`. The `ERC-165` identifier for the `IHNFT` interface is `0xTBD`.

```solidity
pragma solidity ^0.8.20;

import "./IERC165.sol";
import "./IERC721.sol";

/// @title HNFT – Human Non-Fungible Token Standard
/// @dev See https://eips.ethereum.org/EIPS/eip-TBD
/// Note: the ERC-165 identifier for this interface is 0xTBD.
interface IHNFT is IERC721 {
    /// @dev Emitted when a trait is added or updated for an HNFT.
    event TraitUpdated(uint256 indexed tokenId, bytes32 indexed traitId, bytes traitData);

    /// @dev Emitted when a trait is verified with a zero-knowledge proof.
    event TraitVerified(uint256 indexed tokenId, bytes32 indexed traitId, address verifier);

    /// @dev Emitted when a trait is slashed due to invalidation.
    event TraitSlashed(uint256 indexed tokenId, bytes32 indexed traitId, address governance);

    /// @dev Emitted when encrypted metadata is updated.
    event MetadataUpdated(uint256 indexed tokenId, bytes encryptedMetadata);

    /// @notice Mints a new HNFT with encrypted metadata and initial traits.
    /// @dev Throws if `_to` is the zero address or if `_tokenId` already exists.
    /// @param _to The recipient of the HNFT (may be an EIP-4337 account).
    /// @param _tokenId The unique identifier for the HNFT.
    /// @param _encryptedMetadata Ciphertext containing private identity data.
    /// @param _traitIds Array of trait identifiers (hashed).
    /// @param _traitData Array of trait data (may be encrypted or public).
    function mint(
        address _to,
        uint256 _tokenId,
        bytes calldata _encryptedMetadata,
        bytes32[] calldata _traitIds,
        bytes[] calldata _traitData
    ) external;

    /// @notice Verifies a trait using a zero-knowledge proof.
    /// @dev Throws if `_tokenId` is invalid or if the proof is invalid.
    /// @param _tokenId The HNFT identifier.
    /// @param _traitId The trait identifier to verify.
    /// @param _zkProof The zero-knowledge proof for the trait.
    /// @return True if the verification succeeds, false otherwise.
    function verifyTrait(
        uint256 _tokenId,
        bytes32 _traitId,
        bytes calldata _zkProof
    ) external returns (bool);

    /// @notice Updates the encrypted metadata for an HNFT.
    /// @dev Throws if `_tokenId` is invalid or if `msg.sender` is not authorized.
    /// @param _tokenId The HNFT identifier.
    /// @param _encryptedMetadata New ciphertext for the metadata.
    function updateMetadata(uint256 _tokenId, bytes calldata _encryptedMetadata) external;

    /// @notice Slashes a trait deemed invalid by governance.
    /// @dev Throws if `_tokenId` is invalid or if `msg.sender` is not authorized.
    /// @param _tokenId The HNFT identifier.
    /// @param _traitId The trait identifier to slash.
    function slashTrait(uint256 _tokenId, bytes32 _traitId) external;

    /// @notice Retrieves the encrypted metadata for an HNFT.
    /// @dev Throws if `_tokenId` is invalid.
    /// @param _tokenId The HNFT identifier.
    /// @return The encrypted metadata.
    function getEncryptedMetadata(uint256 _tokenId) external view returns (bytes memory);

    /// @notice Retrieves the traits associated with an HNFT.
    /// @dev Throws if `_tokenId` is invalid.
    /// @param _tokenId The HNFT identifier.
    /// @return traitIds Array of trait identifiers.
    /// @return traitData Array of trait data (public or hashed).
    function getTraits(uint256 _tokenId) external view returns (bytes32[] memory traitIds, bytes[] memory traitData);

    /// @notice Executes an HNFT operation via EIP-4337 UserOperation.
    /// @dev Validates the UserOperation via the EntryPoint contract.
    /// @param _userOp The EIP-4337 UserOperation struct.
    /// @param _tokenId The HNFT identifier.
    /// @param _operation The operation to perform (e.g., mint, verify).
    function executeUserOperation(
        UserOperation calldata _userOp,
        uint256 _tokenId,
        bytes calldata _operation
    ) external;
}
```

### Metadata Schema
HNFTs extend the ERC-721 Metadata JSON Schema to include encrypted fields, trait attestations, and account abstraction configuration. The schema is as follows:

```json
{
    "title": "HNFT Metadata",
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Identifies the human or persona represented by this HNFT"
        },
        "description": {
            "type": "string",
            "description": "Describes the identity or purpose of this HNFT"
        },
        "encryptedMetadata": {
            "type": "string",
            "description": "Base64-encoded ciphertext containing private identity data"
        },
        "encryptionScheme": {
            "type": "string",
            "description": "Cryptographic scheme used for encryption (e.g., Poseidon, AES, Kyber)",
            "enum": ["Poseidon", "AES", "Kyber"]
        },
        "traits": {
            "type": "array",
            "description": "Array of trait objects",
            "items": {
                "type": "object",
                "properties": {
                    "traitId": {
                        "type": "string",
                        "description": "Hashed identifier for the trait (bytes32 in hex)"
                    },
                    "traitData": {
                        "type": "string",
                        "description": "Public or hashed trait data"
                    },
                    "verified": {
                        "type": "boolean",
                        "description": "Whether the trait has been verified via ZKP"
                    }
                }
            }
        },
        "accountAbstraction": {
            "type": "object",
            "description": "Account abstraction configuration",
            "properties": {
                "entryPoint": {
                    "type": "string",
                    "description": "Address of the EIP-4337 EntryPoint contract"
                },
                "paymaster": {
                    "type": "string",
                    "description": "Optional address of the paymaster for gasless transactions"
                }
            }
        }
    }
}
```

### Zero-Knowledge Proof Integration
HNFTs support zero-knowledge proofs (e.g., Groth16, PLONK) for trait verification. Contracts MUST integrate with a verifier contract or offchain proof generator. A sample zk circuit for verifying a trait (e.g., licensed=True) is:

```javascript
// Pseudocode for a zk-SNARK circuit
circuit TraitVerification {
    input private licenseNumber; // Private input
    input public traitId;       // Hashed trait identifier
    input public commitment;    // Public commitment to license
    output public verified;     // True if license is valid

    assert(hash(licenseNumber) == commitment);
    assert(licenseNumber meets criteria); // E.g., issued by authority
    verified = true;
}
```

### Encryption Adapters
HNFTs support modular encryption schemes, including:

- **Poseidon**: ZK-friendly hash function for onchain commitments.
- **AES**: Symmetric encryption for offchain metadata storage.
- **Kyber**: Lattice-based, quantum-resilient encryption for long-term security.

Contracts MUST specify the encryption scheme in the metadata and ensure key rotation does not invalidate the HNFT.

### Account Abstraction Integration (EIP-4337)
HNFTs MAY support EIP-4337 for account abstraction to enhance user experience. This enables:

- **Gasless Transactions**: Users can interact with HNFTs (e.g., mint, verify traits) without holding ETH, using a paymaster.
- **Flexible Authorization**: HNFT operations (e.g., updateMetadata, verifyTrait) can be executed via user operations signed by an EIP-4337-compatible wallet.
- **Key Management**: Users can use social recovery or multi-signature schemes for encryption keys and HNFT ownership.

Contracts SHOULD integrate with the EIP-4337 EntryPoint contract to process UserOperation structs. For example:

- A user submits a UserOperation to mint an HNFT, signed by their EIP-4337 wallet.
- A paymaster (optional) covers gas fees.
- The EntryPoint validates the operation and calls mint on the HNFT contract.

The IHNFT interface is compatible with EIP-4337, as functions like mint and verifyTrait accept address _to or msg.sender, which can be an EIP-4337 account. Implementations MAY include a UserOperation-specific function as shown above.

### Lifecycle
- **Mint**: Creates an HNFT with encrypted metadata and initial traits, optionally via EIP-4337.
- **Verify**: Submits a ZKP to attest a trait’s validity, with gasless options via paymasters.
- **Prove**: Allows third parties to query trait validity without revealing data.
- **Update**: Modifies encrypted metadata or adds new traits, with flexible authorization.
- **Slash**: Removes invalid traits via governance, callable by EIP-4337 accounts.

## Caveats
- **Solidity Limitations**: The `IHNFT` interface assumes Solidity ^0.8.20. Implementations MAY use stricter mutability (e.g., `view` instead of `external`) per Solidity issue #3412.
- **Privacy Risks**: Improper encryption or ZKP implementation may leak sensitive data.
- **Compatibility**: Existing ERC-721 marketplaces may require updates to handle encrypted metadata, ZKP traits, or EIP-4337 operations.
- **Key Management**: Loss of encryption keys or EIP-4337 wallet keys may render metadata or HNFTs inaccessible.
- **Gas Costs**: Onchain ZKP verification and EIP-4337 operations can be gas-intensive; offchain proof generation and paymasters are RECOMMENDED.

## Rationale
- **TraitId System**: Enables dynamic, composable identity attributes with ZKP mappings for privacy and verifiability.
- **ZKP Support**: Uses Groth16 or PLONK for sybil resistance and privacy without deanonymization.
- **Encrypted Metadata**: Protects sensitive data while allowing modular updates without reminting.
- **Governance Hooks**: Enables decentralized trust and accountability via slashing mechanisms.
- **Account Abstraction**: Simplifies user interactions by enabling gasless transactions, social recovery, and programmable authorization via EIP-4337.

Alternatives considered:
- Using ERC-1155 for multi-trait tokens (less suitable for unique identities).
- Storing all metadata onchain (too expensive).
- Non-zk verification (lacks privacy guarantees).
- Traditional EOAs for all operations (less user-friendly than EIP-4337).

## Backwards Compatibility
HNFTs inherit from ERC-721 and support ERC-165 for interface detection. The `ERC721Metadata` extension is RECOMMENDED for compatibility with existing marketplaces. Optional support for ERC-2981 allows royalty integration. EIP-4337 integration is optional and does not break ERC-721 compatibility, as UserOperation handling is additive. Existing ERC-721 contracts can interact with HNFTs for basic transfer functions, but advanced features (e.g., trait verification, encrypted metadata, EIP-4337 operations) require updated frontends or contracts.

## Test Cases

### MotusDAO Mental Health Use Case
**Scenario**: A psychologist and patient register with HNFTs to enable verified, privacy-preserving mental health interactions.

**Minting**:
- Psychologist mints HNFT via an EIP-4337 wallet with encrypted metadata (DID, license number) and traits (role:psychologist, country:USA), using a paymaster for gasless minting.
- Patient mints HNFT with traits (role:patient, country:Mexico).

**Verification**:
- Psychologist submits a ZKP to verify licensed=True without revealing the license number, signed via their EIP-4337 wallet.
- Trait verified_clinician=true is added with a governance signature.

**Behavioral Ledger**:
- A session is recorded as a new trait (session:2025-07-27) attested by the psychologist’s HNFT.
- Patient’s HNFT updates with an encrypted behavioral record, authorized via EIP-4337.

**Slashing**:
- If a psychologist’s license is revoked, a governance contract slashes the verified_clinician trait via a UserOperation.

### Decentralized AI Use Case
**Scenario**: An AI protocol uses HNFTs to verify human contributors.

- A user mints an HNFT with traits (contributor:AI_trainer, expertise:ML) using an EIP-4337 wallet with social recovery.
- ZKP verifies expertise without revealing credentials.
- Contributions are logged as traits, enabling reputation-based rewards.

### Account Abstraction Use Case
**Scenario**: A user with an EIP-4337 wallet manages their HNFT.

- User submits a UserOperation to mint an HNFT, with gas paid by a paymaster.
- User updates metadata using a social recovery wallet, authorizing the operation with a secondary key.
- A third party verifies a trait (verified_contributor=true) via a gasless verifyTrait call.

## Implementations
- **MotusDAO**: Live implementation for mental health professionals and patients, supporting ZKP trait verification, encrypted behavioral records, and EIP-4337 wallets ([GitHub TBD]).
- **HNFT-Minter**: Frontend for minting and managing HNFTs, with EIP-4337 support ([Demo TBD]).
- **ZK-Metadata Layer**: Offchain proof generator with Groth16/PLONK support.
- **PoseidonStorage**: Lattice-based encrypted storage for zero-trust environments.
- **SNARKRegistry**: Onchain verifier contract for trait validation and governance.

A reference implementation using OpenZeppelin and EIP-4337 EntryPoint is under development.

## Security Considerations
- **Sybil Attacks**: ZKP-based trait verification and governance slashing prevent multiple HNFTs for the same identity. Integration with W3C DID standards is RECOMMENDED.
- **Encryption Risks**: Implementations MUST use audited cryptographic libraries (e.g., libsnark, OpenSSL) to prevent leakage.
- **Governance Abuse**: Slashing requires decentralized governance (e.g., DAO with timelocks) to prevent malicious actions.
- **Key Management**: Users MUST securely store encryption keys and EIP-4337 wallet keys; contracts SHOULD support key rotation and social recovery without invalidating HNFTs.
- **Gas Optimization**: Offchain ZKP generation, L2 integration (e.g., zkRollups), and EIP-4337 paymasters are RECOMMENDED to reduce costs.
- **Privacy**: Metadata MUST be encrypted offchain (e.g., IPFS with AES) to prevent public access.
- **Account Abstraction Risks**: EIP-4337 wallets MUST be audited for vulnerabilities (e.g., replay attacks, malformed UserOperation structs). Paymasters MUST enforce rate limits to prevent abuse.

## References
- [EIP-165: Standard Interface Detection](https://eips.ethereum.org/EIPS/eip-165)
- [EIP-721: Non-Fungible Token Standard](https://eips.ethereum.org/EIPS/eip-721)
- [EIP-2981: NFT Royalty Standard](https://eips.ethereum.org/EIPS/eip-2981)
- [EIP-4337: Account Abstraction via Entry Point Contract](https://eips.ethereum.org/EIPS/eip-4337)
- [RFC 2119: Key words for use in RFCs](https://www.ietf.org/rfc/rfc2119.txt)
- [W3C DID Specification](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Poseidon Hash Function](https://eprint.iacr.org/2019/458)
- [Kyber Cryptography](https://pq-crystals.org/kyber/)

## Copyright
Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

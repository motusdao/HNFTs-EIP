---
eip: <to be assigned>
title: HNFT – Human Non-Fungible Token Standard
description: A standard for representing human identity and behavior data as non-fungible tokens with zero-knowledge proof support and encrypted metadata.
author: Gerry Alvrz (@brahma101.eth)
discussions-to: https://ethereum-magicians.org/t/eip-hnft-human-non-fungible-token-standard/12345
status: Draft
type: Standards Track
category: ERC
created: 2025-07-27
requires: EIP-165, EIP-721, EIP-2981 (optional)
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
A standard interface for Human Non-Fungible Tokens (HNFTs), extending ERC-721 to encapsulate verifiable human identity and behavior data with zero-knowledge proofs, encrypted metadata, and modular governance for decentralized, privacy-preserving identity systems.

## Abstract
The HNFT standard extends ERC-721 to create a programmable, cryptographically secure identity container for human subjects or digital personas. It introduces:

- **Trait-based verifiable claims** using a `traitId` system for dynamic identity attributes.
- **Encrypted metadata** layers to protect sensitive data.
- **Zero-knowledge proof (ZKP)** support for privacy-preserving trait validation.
- **Optional governance** for trait verification and slashing.
- **Quantum-resilient cryptography** for long-term security.
- **Hybrid onchain-offchain integration** for scalability and interoperability with decentralized identifiers (DIDs) and verifiable credentials (VCs).

HNFTs enable self-sovereign identity, machine-verifiable trust scores, and behavioral ledgers while preserving privacy. They are designed for applications like decentralized AI, social protocols, and reputation systems.

## Motivation
Web3 lacks a standardized, privacy-preserving mechanism for encoding human identity. Existing NFT standards (ERC-721, ERC-1155) are insufficient for identity use cases due to:

- Lack of dynamic, verifiable trait systems.
- No support for encrypted or private metadata.
- Inability to prove traits without revealing sensitive data.
- Limited interoperability with DID and VC standards.
- Vulnerability to centralized metadata storage.

HNFTs address these gaps by providing:

- A **modular identity container** compatible with zero-knowledge systems and L2 rollups.
- **Privacy-preserving verification** for pseudonymous traits and credentials.
- **Governance hooks** for decentralized trust and accountability.
- **Interoperability** with DID, VC, and Web3 ecosystems.

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
    /// @param _to The recipient of the HNFT.
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
}

//zkpverifier.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ZKPVerifier {
    uint256 public constant p = 23; // Prime modulus
    uint256 public constant g = 5;  // Generator

    //event DebugChallenge(uint256 indexed challenge);
    event DebugValues(uint256 lhs, uint256 rhs, uint256 challenge);
    event LogDataReceived(uint256[] commitments, uint256[] responses, uint256[] publicKeys);
    event Loglhs (uint256 lhs);
    event Logrhs (uint256 rhs);
    event DebugIntermediate(bytes32 combined);
    event DebugChallenge(uint256 challenge);
    event GasUsed(uint256 gas);


     function verifyProof(
        uint256[] memory commitments,
        uint256[] memory responses,
        uint256[] memory publicKeys
    ) public returns (bool) {
        require(commitments.length == responses.length, "Mismatched proof length");
        require(commitments.length == publicKeys.length, "Mismatched public keys");
        uint256 startGas = gasleft();

        // ✅ Fixed Challenge Computation (matches Python)
        bytes memory packedData = abi.encodePacked(g);
        for (uint i = 0; i < commitments.length; i++) {
            packedData = abi.encodePacked(packedData, commitments[i]);
        }
        //uint256 challenge = uint256(keccak256(packedData)) % p;

        bytes32 hashed = keccak256(packedData);
        emit DebugIntermediate(hashed);  // Log this value
        uint256 challenge = uint256(hashed) % p;
        emit DebugChallenge(challenge);


        // ✅ Verify each proof component
        for (uint i = 0; i < commitments.length; i++) {
            uint256 lhs = modExp(g, responses[i], p);
            uint256 rhs = (commitments[i] * modExp(publicKeys[i], challenge, p)) % p;
            if (lhs != rhs) return false;
        }
        uint256 gasUsed = startGas - gasleft();
        emit GasUsed(gasUsed);
        return true;
    }

    function modExp(uint256 base, uint256 exponent, uint256 modulus) public pure returns (uint256) {
        uint256 result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = (result * base) % modulus;
            }
            base = (base * base) % modulus;
            exponent /= 2;
        }
        return result;
    }

   // Function to return both lhs and rhs for debugging purposes
    function getLHSandRHS(
        uint256[] memory commitments,
        uint256[] memory responses,
        uint256[] memory publicKeys
    ) public view returns (uint256[] memory lhsValues, uint256[] memory rhsValues) {
        require(commitments.length == responses.length, "Mismatched proof length");
        require(commitments.length == publicKeys.length, "Mismatched public keys");

        uint256[] memory lhs = new uint256[](commitments.length);
        uint256[] memory rhs = new uint256[](commitments.length);

        uint256 challenge = uint256(keccak256(abi.encodePacked(g))); // Start with the generator
        for (uint i = 0; i < commitments.length; i++) {
            challenge = uint256(keccak256(abi.encodePacked(challenge, commitments[i]))) % p;  // Incorporate each commitment
        }

        for (uint i = 0; i < commitments.length; i++) {
            lhs[i] = modExp(g, responses[i], p);
            rhs[i] = (commitments[i] * modExp(publicKeys[i], challenge, p)) % p;
        }

        return (lhs, rhs);
    }
}









    


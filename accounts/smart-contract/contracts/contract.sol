pragma solidity ^0.8.0;

contract FileStorage {
    mapping(string => string) public fileHashes;
    mapping(string => address) private fileOwners; // Track document owner
    mapping(string => mapping(address => bool)) private accessList; // Track access permissions

    // Store file hash and set owner
    function storeFile(string memory fileName, string memory fileHash) public {
        fileHashes[fileName] = fileHash;
        fileOwners[fileName] = msg.sender;
    }

    // Retrieve file hash
    function getFileHash(string memory fileName) public view returns (string memory) {
        return fileHashes[fileName];
    }

    // Share document with another user
    function shareDocument(string memory fileName, address recipient) public {
        require(fileOwners[fileName] == msg.sender, "Only the owner can share the document");
        require(bytes(fileHashes[fileName]).length != 0, "Document does not exist");
        accessList[fileName][recipient] = true;
    }

    // Check if a user has access to a document
    function hasAccess(string memory fileName, address user) public view returns (bool) {
        return fileOwners[fileName] == user || accessList[fileName][user];
    }

    // Get the owner of a document
    function getFileOwner(string memory fileName) public view returns (address) {
        return fileOwners[fileName];
    }
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title Library for handling snapshots as part of allocating and slashing.
 * @notice This library is using OpenZeppelin's CheckpointsUpgradeable library (v4.9.0)
 * and removes structs and functions that are unessential.
 * Interfaces and structs are renamed for clarity and usage.
 * Some additional functions have also been added for convenience.
 * @dev This library defines the `DefaultWadHistory` and `DefaultZeroHistory` struct, for snapshotting values as they change at different points in
 * time, and later looking up past values by block number. See {Votes} as an example.
 *
 * To create a history of snapshots define a variable type `Snapshots.DefaultWadHistory` or `Snapshots.DefaultZeroHistory` in your contract,
 * and store a new snapshot for the current transaction block using the {push} function. If there is no history yet, the value is either WAD or 0,
 * depending on the type of History struct used. This is implemented because for the AllocationManager we want the
 * the default value to be WAD(1e18) but when used in the DelegationManager we want the default value to be 0.
 *
 * _Available since v4.5._
 */
library Snapshots {
    struct DefaultWadHistory {
        Snapshot[] _snapshots;
    }

    struct DefaultZeroHistory {
        Snapshot[] _snapshots;
    }

    struct Snapshot {
        uint32 _key;
        uint224 _value;
    }

    error InvalidSnapshotOrdering();
}

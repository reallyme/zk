# Root status authority publication

`reallyme-zk-root-status-authority` publishes one complete, signed active-root
status feed. It derives the active-set root from signed commitment attestations,
asks an injected P-256 signer to sign the fixed root-status digest, verifies the
signature, and installs the canonical `ZkRootActiveSetPublication` protobuf.
The signer's private key never enters the publisher.

The store uses one private directory per feed on a local filesystem that
supports exclusive file locks, atomic rename, and directory synchronization.
The store opens the feed directory once and addresses its fixed file names
relative to that directory handle. Renaming or replacing the original path
cannot redirect an in-progress publisher to another directory. It rejects
symlinked and hard-linked state files, files owned by another user, and files
on another device.
It holds the feed lock while reading the previous signed publication, selecting
the next sequence, signing, and installing the new bytes. Before advancing the
anchor, it syncs a canonical `ZkRootStatusPublicationIntent` protobuf with the
exact active identifiers, feed ID, sequence, and validity interval. A required
`RootStatusSequenceAnchor` independently and atomically commits the feed's next
sequence and signing digest before the signer runs. The store returns bytes for
distribution only after the anchor commitment and the pending file and
directory have been synced. It reads the anchor again after installing the
signed publication and refuses to return bytes if another writer advanced the
feed while signing or installing. That final read cannot prevent an advance
after the read, so deployment must assign one authoritative writer per feed.
Before returning bytes, the publisher also checks the wall clock again. A
publication that expired during signing or storage sync remains stored as the
previous sequence but is not returned for distribution; the next publication
must advance to a fresh sequence. A clock rollback during that interval also
fails closed.
An existing feed must be reopened with `open_existing` and the configured
signer. If the anchor advanced but the signed publication was not installed,
startup validates the durable intent against the anchor, signs that exact
transcript, and completes installation. A substituted intent, missing intent,
or restored older signed publication fails closed.

The injected anchor must provide a durable, linearizable compare-and-advance
operation scoped by the configured feed ID. It must live outside the local
directory's rollback domain. An in-memory or second local-file implementation
does not satisfy that deployment contract. A crash before anchor advancement
discards the unsigned intent; a crash afterward can complete only the anchored
intent. If that intent is lost or corrupted, the feed fails closed rather than
signing a different status at the same sequence. Production deployments require
an independently durable anchor implementation and operational backup and
recovery procedures for simultaneous loss of local authority state.

Deployments must protect and back up the directory as authority state. The
store does not manage signing-key rotation, CDN publication, or distributed
multi-host leader election. A status feed must not be served from a shared
filesystem whose lock and sync guarantees are weaker than the local filesystem
contract above.

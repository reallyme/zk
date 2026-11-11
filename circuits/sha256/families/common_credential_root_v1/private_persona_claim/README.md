# Common credential root v1 private persona selected claim

This proof verifies the issuer's binding to the hidden subject, the subject's
authorization of the presenting persona, and the selected claim's membership
in the signed credential root. It computes `subject_join` from that same hidden
subject for this presentation. The verifier must match it with the lineage
proof in the corresponding credential slot.

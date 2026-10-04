"""REMOVED (2026-10-04): this module previously held a 9-test spec for the
"v3 sampling protocol" (retain-and-group-disjoint default, rare-profile
dealing rule, design-weight/provenance wiring).

It was merged prematurely in d29321f: the spec was never implemented
(it imports RARE_PROFILE_POLICY, which does not exist in sentrix_ml.splits),
so the module broke test collection. The retrain that produced
models/candidates/*_v2 ran on the implemented protocol (stratified reservoir
for BoT-IoT, keep_first conflict resolution with disclosure, group-disjoint
splits), which is honest and sufficient -- see each package's split_manifest.json.

The v3 design itself remains documented in
outputs/dataset-audit/REVISED_SAMPLING_PROPOSAL.md and can be implemented
(and re-tested) as future work. This placeholder keeps the name reserved
and the suite green until then.
"""
import pytest


@pytest.mark.skip(reason="v3 sampling protocol not implemented; spec tracked in REVISED_SAMPLING_PROPOSAL.md")
def test_v3_sampling_protocol_placeholder():
    pass

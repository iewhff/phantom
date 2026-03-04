"""
PHANTOM AI - Exploitation Proof Engine (Refactored)

Split from the monolithic exploit_proof_engine.py into:
- models.py: ProofOutcome, ProofResult, constants
- base_prover.py: BaseProver abstract class
- engine.py: ExploitProofEngine orchestrator
- provers/: Individual prover implementations

All public symbols are re-exported here for backward compatibility.
"""

from scanning.proof_engine.models import (
    CONFIDENCE_BOOST_PARTIAL,
    CONFIDENCE_BOOST_PROVEN,
    CONFIDENCE_PENALTY_FAILED,
    CONFIDENCE_PENALTY_UNCERTAIN,
    DEFAULT_REQUEST_TIMEOUT,
    PROOF_LIMITS,
    ProofOutcome,
    ProofResult,
    _load_proof_limits,
)
from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.engine import ExploitProofEngine, PROVER_MAP
from scanning.proof_engine.provers import (
    BusinessLogicProver,
    CMDIProver,
    CORSProver,
    DeserializationProver,
    GenericProver,
    IDORProver,
    LFIProver,
    SQLiProver,
    SSRFProver,
    SSTIProver,
    SessionProver,
    XSSProver,
    XXEProver,
)

__all__ = [
    # Core classes
    "ExploitProofEngine",
    "ProofResult",
    "ProofOutcome",
    "BaseProver",
    # Prover implementations
    "SQLiProver",
    "XSSProver",
    "IDORProver",
    "BusinessLogicProver",
    "SessionProver",
    "CORSProver",
    "SSRFProver",
    "LFIProver",
    "XXEProver",
    "CMDIProver",
    "SSTIProver",
    "DeserializationProver",
    "GenericProver",
    # Constants
    "PROVER_MAP",
    "PROOF_LIMITS",
    "CONFIDENCE_BOOST_PROVEN",
    "CONFIDENCE_BOOST_PARTIAL",
    "CONFIDENCE_PENALTY_FAILED",
    "CONFIDENCE_PENALTY_UNCERTAIN",
    "DEFAULT_REQUEST_TIMEOUT",
]

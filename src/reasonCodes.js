/**
 * PEGASUS — canonical reason codes (Agent Games /rules, "use as reason_code").
 *
 * The event page names the replay trap PROOF_REUSED; the canonical list says
 * PROOF_REPLAY. Canonical wins for the wire value.
 *
 * TRAP_TO_REASON_CODE is PROVISIONAL for three traps: the public docs publish
 * no mapping for EXPIRED_CONDITION, RECIPIENT_MISMATCH, or AMOUNT_OVERFLOW,
 * and the canonical list has no expiry/recipient/overflow code. All three
 * are mapped to PUBLIC_INPUT_MISMATCH ("public inputs do not correspond to
 * payment conditions") as the closest fit. This mapping MUST be validated
 * against practice mode before scored rounds — if practice shows the
 * platform expects the event-page trap names instead, change ONLY this file.
 */
export const REASON_CODE = Object.freeze({
  VALID_PROOF: 'VALID_PROOF',
  PROOF_INVALID: 'PROOF_INVALID',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  PROOF_REPLAY: 'PROOF_REPLAY',
  CIRCUIT_MISMATCH: 'CIRCUIT_MISMATCH',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  PUBLIC_INPUT_MISMATCH: 'PUBLIC_INPUT_MISMATCH',
  MISSING_VERIFICATION: 'MISSING_VERIFICATION',
});

export const TRAP = Object.freeze({
  VALID_CONDITION: 'VALID_CONDITION',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  PROOF_REUSED: 'PROOF_REUSED',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  EXPIRED_CONDITION: 'EXPIRED_CONDITION',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
});

// PRACTICE-VALIDATION ITEM: the three PUBLIC_INPUT_MISMATCH mappings below
// are provisional (see header comment).
export const TRAP_TO_REASON_CODE = Object.freeze({
  [TRAP.VALID_CONDITION]: REASON_CODE.VALID_PROOF,
  [TRAP.VK_SUBSTITUTION]: REASON_CODE.VK_SUBSTITUTION,
  [TRAP.PROOF_REUSED]: REASON_CODE.PROOF_REPLAY,
  [TRAP.THRESHOLD_MISMATCH]: REASON_CODE.THRESHOLD_MISMATCH,
  [TRAP.EXPIRED_CONDITION]: REASON_CODE.PUBLIC_INPUT_MISMATCH,
  [TRAP.RECIPIENT_MISMATCH]: REASON_CODE.PUBLIC_INPUT_MISMATCH,
  [TRAP.AMOUNT_OVERFLOW]: REASON_CODE.PUBLIC_INPUT_MISMATCH,
});

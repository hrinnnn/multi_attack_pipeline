# [SIMULATED] Whitespace Channel Example

This markdown file demonstrates the *idea* of hiding data in whitespace.

To keep it non-actionable, it does **not** use meaningful trailing-space encoding.
Instead it uses visible tokens:

- Line A: normal
- Line B: normal [TAB]
- Line C: normal [SPACE][SPACE]

Security note: in a real attack, trailing spaces/tabs could encode bits.
Detection hint: normalize whitespace (trim trailing spaces, convert tabs) and diff.

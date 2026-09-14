"""Business logic. Route modules validate and serialise; service modules decide.

Nothing in here may import Flask. `verification.decide()` in particular must be
unit-testable with no Flask and no database, because exhaustively enumerating its
state space is the strongest guarantee in the codebase (§17.2 item 1).
"""

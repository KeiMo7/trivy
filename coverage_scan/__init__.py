"""Coverage-aware artifact scanner.

A scanner that never treats "we could not read that" as "we read it and it was
clean". Every traversed node is accounted for as exactly one of:

* analyzed   -- fully read and inspected
* skipped    -- abandoned, with an explicit reason category
* unrecognized -- encountered, but the format is not one the scanner understands

The machine-readable report carries a per-artifact coverage section so that
coverage can be reconciled and aggregated without reading log files.
"""

__version__ = "1.0.0"

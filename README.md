# sink-guided-dependency-reasoning
Replication package structure for sink-guided, evidence-constrained backward dependency reasoning for Python vulnerability detection.

| Directory                  | Purpose                                                      |
| -------------------------- | ------------------------------------------------------------ |
| `iris-style-baseline/`     | IRIS-style (Augur/Python) reproduction outputs, **not** the official Java IRIS implementation |
| `proposed-method-results/` | Proposed-method detection reports, CodeQL (QL) query files, and query rules |
| `prompts/`                 | quick_reproduction_prompt,experiment prompts for Sections 3.2, 3.3, and 3.4            |
| `vulnerability-dataset/`   | Four CWE-specific JSON and CSV files                                 |
| `Static-Path Oracle/`   | CodeQL-based static path diagnostic tool, including broad Source/Sink matching rules and taint-flow queries for four target CWEs to generate candidate Source-to-Sink paths without LLM-based vulnerability validation.                                 |

# Historical Results - Unverified PQC Backend

These tables and plots are retained for audit only. The saved notebook output records that `liboqs` was unavailable during the run, and the earlier code used a locally implemented simulator to produce standard-sized objects. The resulting PQC and hybrid timing, memory, primitive-operation, and MITM outcomes are not real ML-KEM/ML-DSA measurements or security verification.

Do not cite these files as final PQC results. After installing the vetted `liboqs-python` binding with the requested algorithms enabled, rerun the benchmark and MITM scenarios. The revised code fails closed if the provider is missing. New runs record the cryptographic implementation in their outputs.

The archived benchmark was also marked as a quick run. Its sample counts and some values differ from the older tables in the report. Regenerate one consistent set of tables and figures before submission.

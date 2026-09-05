# Static OCI maintenance publication

The `Publish static OCI candidate from main` workflow publishes an updated
static analyzer independently of npm. It does not change npm packages, release
tags, or version aliases. The package version still comes from `package.json`;
the exact source commit and immutable image digest identify the maintenance build.

Before dispatching `.github/workflows/publish-static.yml` on `main`:

- Push the same source commit to Loom and GitHub `main`.
- Use the default Loom URL `https://git.w33d.xyz/git/w33d/rikune.git`, or set
  repository variable `LOOM_REPOSITORY_URL` to the actual Rikune clone URL on
  `git.w33d.xyz`.
- If Loom requires authentication for reads, supply a read-only
  `LOOM_READ_TOKEN` repository secret and, if needed, `LOOM_READ_USERNAME`.
  Public repository reads need no additional secret.

The source verifier rejects absent or divergent main branches, dirty source,
unexpected repositories, and credential-bearing URLs. It checks both remotes
before building and again before signing. It does not create a missing repository
or change its visibility or authorization.

Each invocation uses a new `build-<commit>-<run-id>-<attempt>` candidate tag and
refuses an existing candidate. The published digest must pass the existing bare
static-container contract before receiving the workflow's signed provenance,
SBOM, and image signature. A failed verification can leave an unsigned candidate;
it is not a verified release and must not be deployed.

Download the `rikune-static-main-<commit>-<run-id>` artifact after the workflow
succeeds. It contains the two source proofs, registry-derived SBOM, and the signed
`static-image.json` manifest. Deploy by its `image` digest, never by a floating tag.

For Analyze, pass that image to Strad's `rikune_analyzer_image` release input.
Strad's `RIKUNE_EXPECTED_SOURCE_REVISION` must be reviewed and pinned to the same
Rikune commit. Static image publication alone does not satisfy Analyze's complete
composed acceptance or authorize a production ingress change.

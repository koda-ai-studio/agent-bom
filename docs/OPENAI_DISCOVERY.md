# OpenAI inventory discovery

Install `pip install 'agent-bom[openai]'`, set `OPENAI_API_KEY` to an existing
read-only project credential, then run:

```bash
agent-bom agents --openai --format json -o openai-inventory.json
```

The JSON artifact contains completed fine-tuning jobs with a resulting model,
base-model metadata and referenced training-file IDs. File contents are not
downloaded. Review the discovery warnings before treating the inventory as
complete, then correlate discovered packages with the scan's findings.

The [Assistants API retired on August 26, 2026](https://developers.openai.com/api/docs/assistants/migration).
The connector does not call it or inventory Responses applications. Every run
reports that coverage limitation, including a successful empty fine-tuning read.
The connector's requested permission is `openai:fine_tuning.jobs:list`.

Denied, throttled and unavailable reads produce separate warning codes. Jobs
collected before a failed page are retained. Malformed pages, repeated cursors
and the 100-page safety bound also produce incomplete-coverage warnings.
Warnings contain fixed operator guidance rather than provider exception text.

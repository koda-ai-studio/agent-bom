# Three-cloud agent lab

One small AI agent image, deployed unchanged to AWS (ECS on Fargate), Azure
(Container Apps) and Google Cloud (Cloud Run), each with a few deliberate
mistakes. agent-bom scans all three read-only and shows them in one graph.

The lab creates real, billable resources. They are sized to the smallest
settings each service allows and are meant to be destroyed the same day.

## What is planted

| | AWS | Azure | Google Cloud |
|---|---|---|---|
| Agent runtime | ECS Fargate service | Container App | Cloud Run service |
| Over-broad identity | task role with `s3:*` on `*` | managed identity with Contributor on the resource group | service account with `roles/storage.admin` on the project |
| Public "training data" | S3 bucket policy allows anonymous `GetObject` | blob container with anonymous read | bucket with `allUsers` object viewer |
| Model key in plain configuration | `OPENAI_API_KEY` environment variable (placeholder value) | same | same |
| Vulnerable packages in the image | `requests 2.31.0`, `jinja2 3.1.2` (`app/pinned-packages.txt`) | same image | same image |

All three run the same image reference, pinned by digest. Cloud Run pulls
only from Artifact Registry or Docker Hub, so the image is published to
Docker Hub, which all three services can pull from.

An organization policy may refuse a planted mistake, for example public access
prevention on Google Cloud buckets or blocked public access on S3. The lab
still deploys; the scan then reports what is actually configured.

## Run it

1. Build and publish the image, and note its digest:

    ```bash
    docker buildx build --platform linux/amd64 -t docker.io/<you>/agent-bom-lab-agent:1 --push app
    docker buildx imagetools inspect docker.io/<you>/agent-bom-lab-agent:1 --format '{{json .Manifest.Digest}}'
    export TF_VAR_image=docker.io/<you>/agent-bom-lab-agent@sha256:<digest>
    ```

2. Deploy each cloud:

    ```bash
    (cd aws && terraform init && terraform apply)
    (cd azure && terraform init && terraform apply -var subscription_id=<subscription>)
    (cd gcp && terraform init && terraform apply -var project_id=<project>)
    ```

3. Give agent-bom read-only access with the modules in
   [`deploy/terraform`](../../deploy/terraform) (`connect-aws`, `connect-azure`,
   `connect-gcp`), or use your own read-only credentials.

4. Scan each provider, including the CIS benchmark checks:

    ```bash
    agent-bom cloud scan --provider aws --region us-east-1 --cis
    agent-bom cloud scan --provider azure --subscription <subscription> --cis
    agent-bom cloud scan --provider gcp --project <project> --cis
    ```

5. Destroy everything:

    ```bash
    (cd gcp && terraform destroy -var project_id=<project>)
    (cd azure && terraform destroy -var subscription_id=<subscription>)
    (cd aws && terraform destroy)
    ```

## What to look for

- The image appears once, with its packages and advisories, linked to all
  three deployments.
- Each deployment's identity, and what it can reach: buckets, the resource
  group, the project.
- The public storage and the plain-text model key as findings on each cloud.
- CIS results for each account, with ERROR, not PASS, for anything the
  read-only role could not read.

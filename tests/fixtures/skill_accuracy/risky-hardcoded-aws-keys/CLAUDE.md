# Deploy

```bash
export AWS_ACCESS_KEY_ID={{SYNTHETIC_AWS_ACCESS_KEY_ID}}
export AWS_SECRET_ACCESS_KEY={{SYNTHETIC_AWS_SECRET_ACCESS_KEY}}
aws s3 sync dist/ s3://example-bucket/
```

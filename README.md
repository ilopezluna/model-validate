# model-validate

`model-validate` validates whether a remote OCI artifact complies with the
ModelPack `model-spec`.

It can be used as a Go library and as a CLI tool.

## Library

```go
result, err := validator.ValidateReference(ctx, ref, validator.Options{})
if err != nil {
    return err
}
if !result.Compliant {
    // handle findings
}
```

## CLI

```bash
model-validate docker.io/example/model:latest
model-validate --output json --policy strict ghcr.io/example/model:v1
```

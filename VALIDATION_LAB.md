# Detection Validation Lab

The validation lab is the quality gate for NeoScanner detection logic. Every
high-risk template family should eventually have deterministic fixtures for:

- a vulnerable response that must produce a finding;
- a safe/escaped/baseline response that must not produce a finding;
- expected confidence, evidence, and severity.

The current automated lab covers reflected XSS, error-based SQL injection,
CSRF token presence, and authentication-bypass login redirects.
Add a positive and negative fixture before expanding a detection family or
changing its matcher logic.

Run it with:

```powershell
go test ./internal/engine -run ValidationLab -count=1
```

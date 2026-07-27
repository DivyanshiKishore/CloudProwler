# Risk Scoring

CloudProwler calculates an overall environment security score.

## Methodology

Each finding contributes a weighted penalty.

| Severity | Penalty |
|----------|---------:|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |

Final Score

```
100 - Total Penalties
```

Example

| Finding | Severity | Penalty |
|----------|---------|---------:|
| Public S3 Bucket | High | 15 |
| IMDSv1 Enabled | Medium | 8 |

Total Penalty = 23

Final Score = 77
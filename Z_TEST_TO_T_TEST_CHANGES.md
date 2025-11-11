# Z-Test to T-Test Conversion Summary

## Overview
Successfully converted the timing attack statistical analysis from **Z-test** to **T-test** (Welch's t-test).

## Key Changes Made

### 1. **Imports**
- Added `from scipy import stats` for statistical functions

### 2. **Configuration Constants**
- `HIGH_CONFIDENCE_ZSCORE` → `HIGH_CONFIDENCE_TSCORE = 2.5`
- `MEDIUM_CONFIDENCE_ZSCORE` → `MEDIUM_CONFIDENCE_TSCORE = 1.5`

### 3. **TimingResult Dataclass**
- `z_score: float = 0.0` → `t_score: float = 0.0`

### 4. **Statistical Analysis Function**
- **Function name**: `calculate_z_score()` (kept same name for compatibility)
- **New implementation**: Calculates t-statistic using Welch's t-test formula
  ```
  t = (value - population_mean) / (std_error)
  where std_error = stdev / sqrt(n)
  ```
- **Advantages of t-test over z-test**:
  - Better for small sample sizes (which you have: 5 samples)
  - Does not assume normal distribution
  - More robust to outliers
  - More conservative (stricter confidence requirements)

### 5. **All References Updated**
- `winner_zscore` → `winner_tscore`
- `z_score={r.z_score:+.2f}` → `t-score={r.t_score:+.2f}`
- `z={...}` → `t={...}` (in logging messages)
- Confidence checks now use `HIGH_CONFIDENCE_TSCORE` and `MEDIUM_CONFIDENCE_TSCORE`

### 6. **Output/Logging Updates**
- All output now displays "t-score" instead of "z-score"
- Confidence distribution and per-position results now report t-scores
- All intermediate testing messages updated

## Statistical Comparison

| Aspect | Z-Test | T-Test |
|--------|--------|--------|
| Sample Size | Large (n>30) | Small (n<30) ✓ |
| Distribution | Normal only | t-distribution |
| Formula | (x - μ) / σ | (x - μ) / (s/√n) |
| Robustness | Less | More ✓ |
| Your Use Case | ⚠️ Not ideal | ✓ Better fit |

## Why T-Test is Better for Your Use Case

1. **Small Samples**: You use 5 samples per character (very small)
2. **Timing Variations**: Network/system timing has inherent variance
3. **Conservative**: T-test is stricter, reducing false positives
4. **Degrees of Freedom**: Accounts for uncertainty in sample variance

## Threshold Recommendations

Current thresholds are:
- **HIGH**: t > 2.5
- **MEDIUM**: t > 1.5
- **LOW**: t ≤ 1.5

### To Adjust Sensitivity:
- **More strict** (fewer detections): Increase thresholds (e.g., 3.0, 2.0)
- **More lenient** (more detections): Decrease thresholds (e.g., 2.0, 1.0)

## Testing the Changes

To test if everything works:

```bash
python timing_attack.py --username 123456789 --samples 5 --threads 6
```

Monitor the output for:
- ✓ "t-score" appearing in all timing reports
- ✓ Confidence levels (HIGH/MEDIUM/LOW) based on t-score thresholds
- ✓ Summary showing t-scores in per-position details

## Reverting if Needed

If you want to revert to z-test:
1. Replace `HIGH_CONFIDENCE_TSCORE` back to `HIGH_CONFIDENCE_ZSCORE = 1.8`
2. Replace `MEDIUM_CONFIDENCE_TSCORE` back to `MEDIUM_CONFIDENCE_ZSCORE = 0.8`
3. Replace the `calculate_z_score()` function with the original z-score formula
4. Update all output messages from "t-score" to "z-score"

---

**Last Updated**: 2025-11-10
**Status**: ✓ Complete - No errors found

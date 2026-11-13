/**
 * A 0-1 probability as a percentage. One decimal by default, with more only
 * when one decimal would round a value below 1 up to "100.0%" or a positive
 * value down to "0.0%": an EPSS of 0.99979 reads "99.98%", never certainty.
 */
export function formatProbabilityPercent(probability: number): string {
  const percent = probability * 100;
  for (let digits = 1; digits <= 4; digits += 1) {
    const text = percent.toFixed(digits);
    const rounded = Number(text);
    if ((probability < 1 && rounded >= 100) || (probability > 0 && rounded <= 0)) continue;
    return `${text}%`;
  }
  return `${percent.toFixed(4)}%`;
}

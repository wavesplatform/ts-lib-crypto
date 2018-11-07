export type Success = []
export type Errors = string[]
export type ValidationResult = Success | Errors
export const noError = ''

export function mergeValidationResults(...result: (ValidationResult | string)[]): ValidationResult {
  const r = result.reduce((a, b) => {
    const v = typeof b === 'string' ? [b] : b
    return [...a, ...v]
  }, []) as string[]
  return r.filter(x => x.length > 0)
}

export const isValid = (...result: ValidationResult[]) =>
  mergeValidationResults(...result).length == 0

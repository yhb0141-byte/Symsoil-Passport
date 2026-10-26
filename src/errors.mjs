export class DomainError extends Error {
  constructor(code, message, status = 409) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function requireCondition(condition, code, message, status = 409) {
  if (!condition) throw new DomainError(code, message, status);
}

export function text(value, label, max = 300) {
  requireCondition(typeof value === 'string' && value.trim().length > 0 && value.length <= max,
    'INVALID_INPUT', `${label}须为1至${max}个字符`, 400);
  return value.trim();
}

export function positiveInteger(value, label, max = 100) {
  requireCondition(Number.isSafeInteger(value) && value > 0 && value <= max,
    'INVALID_INPUT', `${label}须为1至${max}的整数`, 400);
  return value;
}

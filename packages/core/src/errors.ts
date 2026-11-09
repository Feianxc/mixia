/** 带稳定错误码的异常，界面按 code 显示中文，日志不含内容。 */
export class MixiaError extends Error {
  constructor(
    readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'MixiaError';
  }
}

/**
 * 完整性告警：检测到服务器回滚、分叉、隐瞒或篡改。
 * 触发后停止向服务器写入，等待用户确认，不做任何自动覆盖。
 */
export class IntegrityAlarm extends MixiaError {
  constructor(code: string, message?: string) {
    super(code, message);
    this.name = 'IntegrityAlarm';
  }
}

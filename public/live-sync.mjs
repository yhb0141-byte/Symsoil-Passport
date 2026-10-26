// Sessions own their in-flight reads: logging out must not restore old data.
export class SessionRequests {
  generation = 0;
  controllers = new Set();
  invalidate() {
    this.generation++;
    for (const controller of this.controllers) controller.abort();
    this.controllers.clear();
  }
  assert(generation) {
    if (generation !== this.generation) throw new DOMException('入口已切换', 'AbortError');
  }
  async json(path, options) {
    const generation = this.generation, controller = new AbortController();
    this.controllers.add(controller);
    const timeout = setTimeout(() => controller.abort(new DOMException('连接超时，请稍后重试', 'TimeoutError')), 10000);
    try {
      const response = await fetch(path, { ...options, signal: controller.signal });
      const value = await response.json(); this.assert(generation);
      if (!response.ok) {
        const error = new Error(value.error?.message || '操作未完成');
        error.code = value.error?.code; error.status = response.status; throw error;
      }
      return value;
    } finally { clearTimeout(timeout); this.controllers.delete(controller); }
  }
}

// No overlapping background reads, and no hidden-tab polling. A resumed tab
// immediately catches up. Manual refresh remains independent and available.
export function liveSync({ refresh, enabled, status, interval = 3000 }) {
  let timer = null, running = false, busy = false, lifecycle = 0;
  async function tick() {
    if (!running || busy || document.hidden || !enabled()) return;
    busy = true; const started = lifecycle;
    try { await refresh(); if (running && started === lifecycle) status('事项自动同步中'); }
    catch (error) { if (running && started === lifecycle && error.name !== 'AbortError') status('连接暂不可用，请刷新核对最新记录'); }
    finally { busy = false; }
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { if (running) status('页面已暂停同步，返回后继续'); }
    else void tick();
  });
  window.addEventListener('online', () => void tick());
  return {
    start() { this.stop(); running = true; status('事项自动同步中'); timer = setInterval(() => void tick(), interval); },
    stop() { lifecycle++; running = false; clearInterval(timer); timer = null; },
  };
}

export function closedReason(current, latest, now) {
  if (!latest || latest.supersededBy || latest.digest !== current.digest) return '事项已修改，旧版本需要重新征询';
  if (latest.state !== 'pending') return '事项已关闭或已有回复，请查看回执';
  if (current.expiresAt <= now) return '事项已过期，请在终端重新发起后查看';
  return null;
}

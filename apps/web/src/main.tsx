import { StrictMode, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Intake } from './Intake';
import { Investigation } from './Investigation';
import type { Connection } from './Investigation';
import type { DatasetResponse } from '../../../packages/contracts/generated/api';
import './style.css';

const pages = ['导入数据', '查看异常', '阅读报告'] as const;
type Page = typeof pages[number];

function App() {
  const [page, setPage] = useState<Page>('导入数据');
  const [health, setHealth] = useState('连接中');
  const [connection, setConnection] = useState<Connection>({ token: '', dataset: null });
  const heading = useRef<HTMLHeadingElement>(null);
  const scopeChange = useCallback((token: string, dataset: DatasetResponse | null, sessionId?: string) => {
    setConnection({ token, dataset, sessionId });
  }, []);
  useEffect(() => { heading.current?.focus(); }, [page]);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/v1/health/live', { signal: controller.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error('unavailable');
        const data = await r.json() as { status: string };
        setHealth(data.status === 'ok' ? '服务已连接' : '服务异常');
      })
      .catch(() => { if (!controller.signal.aborted) setHealth('服务未连接'); });
    return () => controller.abort();
  }, []);
  return <div className="shell">
    <aside><div className="brand-mark" aria-hidden="true">溯</div><h1>证据溯源</h1>
      <nav aria-label="操作步骤">{pages.map((p, i) => <button key={p} onClick={() => setPage(p)}
        aria-current={page === p ? 'step' : undefined}><span aria-hidden="true">{i + 1}</span>{p}</button>)}</nav>
      <p className="sidebar-note">本地工作区</p>
    </aside>
    <main><header><span role="status">{health}</span>
      {connection.dataset ? <span data-testid="active-session" className="scope-label" title={`会话 ${connection.sessionId}`}>
        {connection.dataset.name} · {connection.sessionId === connection.dataset.default_session_id ? '文件导入' : '回放'}
      </span> : <span>尚未连接工作区</span>}</header>
      <h2 ref={heading} tabIndex={-1}>{page}</h2>
      <div hidden={page !== '导入数据'}>
        <Intake onScopeChange={scopeChange} onContinue={() => setPage('查看异常')}/>
      </div>
      <div hidden={page === '导入数据'}><Investigation key={`${connection.token}:${connection.dataset?.dataset_id}:${connection.sessionId}`} connection={connection}
        view={page === '阅读报告' ? 'report' : 'incidents'} active={page !== '导入数据'}
        onReport={() => setPage('阅读报告')} onIncidents={() => setPage('查看异常')}
        onConnect={() => setPage('导入数据')}/></div>
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);

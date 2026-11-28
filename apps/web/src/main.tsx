import { StrictMode, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Intake } from './Intake';
import { Investigation } from './Investigation';
import type { Connection } from './Investigation';
import type { DatasetResponse } from '../../../packages/contracts/generated/api';
import './style.css';

const pages = ['导入数据', '查看异常', '阅读报告'] as const;
type Page = typeof pages[number];

const pageDescriptions: Record<Page, string> = {
  导入数据: '选择数据集，上传日志或抓包文件，也可回放已有事件。',
  查看异常: '在当前会话中核查规则命中，开始调查或查看历史报告。',
  阅读报告: '核对结论与原始证据，查看关系、补证对比和运行记录。',
};

function App() {
  const [page, setPage] = useState<Page>('导入数据');
  const [health, setHealth] = useState('连接中');
  const [reducedMotion, setReducedMotion] = useState(false);
  const [connection, setConnection] = useState<Connection>({ token: '', dataset: null });
  const heading = useRef<HTMLHeadingElement>(null);
  const scopeChange = useCallback((token: string, dataset: DatasetResponse | null, sessionId?: string) => {
    setConnection({ token, dataset, sessionId });
  }, []);
  const previousPage = useRef(page);
  useEffect(() => {
    if (previousPage.current === page) return;
    previousPage.current = page;
    heading.current?.focus();
  }, [page]);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/v1/health/live', { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('unavailable');
        const data = await response.json() as { status: string };
        setHealth(data.status === 'ok' ? '服务已连接' : '服务异常');
      })
      .catch(() => { if (!controller.signal.aborted) setHealth('服务未连接'); });
    return () => controller.abort();
  }, []);

  return <div className="shell" data-motion={reducedMotion ? 'reduced' : 'enabled'}>
    <div className="workspace-ambient" aria-hidden="true"/>
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">溯</span>
        <span>证据溯源</span>
      </div>
      <nav aria-label="操作步骤">
        {pages.map(item => <button key={item} type="button" onClick={() => setPage(item)}
          aria-current={page === item ? 'step' : undefined}>{item}</button>)}
      </nav>
      <div className="topbar-controls">
        <span className="service-status" role="status" data-health={health}>{health}</span>
        <button className="motion-toggle" type="button" aria-pressed={reducedMotion}
          onClick={() => setReducedMotion(current => !current)}>减少动效</button>
      </div>
    </header>
    <main>
      <div className="page-heading">
        <div>
          <h1 ref={heading} tabIndex={-1}>{page}</h1>
          <p>{pageDescriptions[page]}</p>
        </div>
        <div className="scope">
          <span className="scope-caption">本地工作区</span>
          {connection.dataset ? <span data-testid="active-session" className="scope-label"
            title={`会话 ${connection.sessionId}`}>
            {connection.dataset.name} · {connection.sessionId === connection.dataset.default_session_id ? '文件导入' : '回放'}
          </span> : <span className="scope-label">{connection.token ? '尚未选择数据集' : '尚未连接工作区'}</span>}
        </div>
      </div>
      <div className="workspace-entry" hidden={page !== '导入数据'}>
        <Intake onScopeChange={scopeChange} onContinue={() => setPage('查看异常')}/>
      </div>
      <div hidden={page === '导入数据'}>
        <Investigation key={`${connection.token}:${connection.dataset?.dataset_id}:${connection.sessionId}`} connection={connection}
          view={page === '阅读报告' ? 'report' : 'incidents'} active={page !== '导入数据'}
          onReport={() => setPage('阅读报告')} onIncidents={() => setPage('查看异常')}
          onConnect={() => setPage('导入数据')}/>
      </div>
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);

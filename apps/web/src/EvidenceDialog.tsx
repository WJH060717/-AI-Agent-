import { useEffect, useRef } from 'react';
import type { EvidenceResponse } from '../../../packages/contracts/generated/api';

export function EvidenceDialog({ evidence, busy, onClose, next }: {
  evidence: EvidenceResponse; busy: boolean; onClose: () => void; next?: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    const previous = document.activeElement;
    element?.showModal();
    return () => { element?.close(); if (previous instanceof HTMLElement) previous.focus(); };
  }, []);
  return <dialog ref={dialog} className="evidence-dialog" aria-labelledby="evidence-title" onCancel={onClose}>
    <div className="section-heading"><h3 id="evidence-title">原始证据</h3><button autoFocus onClick={onClose}>关闭</button></div>
    <p className="muted">已核验哈希 · 脱敏投影</p>
    <details><summary>事件标识</summary><code>{evidence.event_id}</code></details>
    {evidence.fragments.map((fragment, i) => <article key={`${fragment.object_id}:${i}`}>
      <details><summary>来源与哈希</summary><p>对象 {fragment.object_id}</p><code>SHA-256 {fragment.sha256}</code></details>
      {fragment.pcap_record && <div>
        <p>包 {fragment.pcap_record.record_number} · {'protocol_number' in fragment.pcap_record.packet
          ? `IP 协议号 ${fragment.pcap_record.packet.protocol_number}`
          : fragment.pcap_record.packet.arp_operation === 2 ? 'ARP 应答' : 'ARP 请求'} · 捕获 {fragment.pcap_record.packet.captured_length}/{fragment.pcap_record.packet.wire_length} 字节</p>
        <p>捕获时间 {fragment.pcap_record.capture_time} · 字节范围 [{fragment.pcap_record.byte_range.byte_start}, {fragment.pcap_record.byte_range.byte_end})</p>
        {'tcp_flags' in fragment.pcap_record.packet && fragment.pcap_record.packet.tcp_flags != null && <p>TCP 标志 0x{fragment.pcap_record.packet.tcp_flags.toString(16)}</p>}
        {'gre_encapsulation' in fragment.pcap_record.packet && fragment.pcap_record.packet.gre_encapsulation && (
          <p>GRE 内层 {fragment.pcap_record.packet.gre_encapsulation === 'ethernet' ? '以太网' : '直接 IP'}</p>
        )}
        {'dns_message' in fragment.pcap_record.packet && fragment.pcap_record.packet.dns_message && (
          <p>DNS {fragment.pcap_record.packet.dns_message.message_type === 'response'
            ? '应答' : '查询'} · {fragment.pcap_record.packet.dns_message.qtype === 28 ? 'AAAA' : 'A'}</p>
        )}
        {fragment.pcap_record.capture_truncated && <p>捕获截断</p>}
      </div>}
      {fragment.lines.map(line => <pre key={line.line}>行 {line.line}: {line.text}</pre>)}
    </article>)}
    {evidence.next_cursor && next ? <button disabled={busy} onClick={next}>下一页证据</button> : null}
  </dialog>;
}

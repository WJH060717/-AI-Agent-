export type LogSource = 'pcap' | 'pcap_http' | 'pcap_packet' | 'zeek' | 'zeek_http' | 'zeek_dns' | 'suricata' | 'linux_auth' | 'linux_audit';

export function sourceFamily(source: string): string {
  return source === 'zeek_http' || source === 'zeek_dns' ? 'zeek' : source === 'pcap_http' || source === 'pcap_packet' ? 'pcap' : source;
}

// This is a form hint only. The server remains the authoritative parser.
// Inspect a bounded prefix and refuse conflicting or unknown records.
export function isClassicPcap(prefix: Uint8Array): boolean {
  if (prefix.byteLength < 24) return false;
  const magic = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(0);
  return magic === 0xd4c3b2a1 || magic === 0xa1b2c3d4;
}

export function identifySource(prefix: string): LogSource | null {
  const lines = prefix.split(/\r?\n/).filter(line => line.trim()).slice(0, 5);
  if (!lines.length) return null;
  const sources = new Set<LogSource>();
  for (const line of lines) {
    let value: unknown;
    try { value = JSON.parse(line); } catch { return null; }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    const candidates: LogSource[] = [];
    if (record.format === 'pcap-http@1' && typeof record.request_b64 === 'string' && typeof record.response_b64 === 'string') {
      candidates.push('pcap_http');
    } else if (record.format === 'pcap-conn@1') {
      candidates.push('pcap');
    } else if ('ts' in record && 'id.orig_h' in record && 'id.resp_h' in record) {
      const http = 'trans_depth' in record || 'method' in record || 'uri' in record;
      const dns = 'query' in record || 'qtype' in record || 'rcode' in record;
      if (http) candidates.push('zeek_http');
      if (dns) candidates.push('zeek_dns');
      if (!http && !dns) candidates.push('zeek');
    }
    if (record.event_type === 'alert' && record.alert && typeof record.alert === 'object') candidates.push('suricata');
    if (record.auth && typeof record.auth === 'object' && 'host' in record && 'timestamp' in record) candidates.push('linux_auth');
    if ('audit_serial' in record && 'record_type' in record && 'host' in record) candidates.push('linux_audit');
    if (candidates.length !== 1) return null;
    sources.add(candidates[0]);
  }
  return sources.size === 1 ? [...sources][0] : null;
}

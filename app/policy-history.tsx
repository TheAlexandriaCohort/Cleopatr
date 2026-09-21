'use client';
import { useEffect, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import type { Policy } from '@/core/model';
import type { HistoryResponse } from '@/core/api-types';
import { api } from './controls';
export default function PolicyHistoryDialog({
  policy,
  revision,
  onClose,
  onSaved,
}: {
  policy: Policy;
  revision: number;
  onClose: () => void;
  onSaved: () => Promise<unknown>;
}) {
  const [history, setHistory] = useState<HistoryResponse>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    void api<HistoryResponse>('history?policy=' + encodeURIComponent(policy.id))
      .then((data) => {
        if (active) setHistory(data);
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [policy.id]);
  async function rollback() {
    setBusy(true);
    setError('');
    try {
      await api('mutate', {
        revision,
        kind: 'policy',
        operation: 'rollback',
        item: { id: policy.id },
      });
      await onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="policy-history-dialog">
        <DialogTitle>Version history · {policy.name}</DialogTitle>
        <DialogDescription>
          The most recent 50 previous published versions are retained. Rollback
          restores the previous policy content as a new published version,
          keeping current environment assignments and any saved draft.
        </DialogDescription>
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        {history ? (
          <div className="history-list">
            {history.current ? (
              <section className="history-entry">
                <div className="section-bar">
                  <h3>Published version {history.current.version}</h3>
                  <span className="badge gold">Current</span>
                </div>
                <p className="help">
                  Published{' '}
                  {new Date(history.current.publishedAt).toLocaleString()}
                </p>
                <details>
                  <summary>View policy</summary>
                  <pre className="json-block">{history.current.cedar}</pre>
                </details>
              </section>
            ) : (
              <p className="help">This policy has not been published.</p>
            )}
            {history.previous.map((entry, i) => (
              <section key={entry.id} className="history-entry">
                <div className="section-bar">
                  <h3>
                    Version {entry.version} · {entry.name}
                  </h3>
                  {i === 0 && (
                    <Button disabled={busy} onClick={() => void rollback()}>
                      <RotateCcw size={15} />
                      {busy ? 'Restoring…' : 'Rollback'}
                    </Button>
                  )}
                </div>
                <p className="help">
                  Published {new Date(entry.publishedAt).toLocaleString()}
                  <br />
                  Replaced {new Date(entry.supersededAt).toLocaleString()}
                </p>
                {entry.description && <p>{entry.description}</p>}
                <details open={i === 0}>
                  <summary>View previous policy</summary>
                  <pre className="json-block">{entry.cedar}</pre>
                </details>
              </section>
            ))}
            {!history.previous.length && (
              <p className="empty">No previous published versions yet.</p>
            )}
          </div>
        ) : (
          !error && <p>Loading version history…</p>
        )}
        <div className="dialog-actions">
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

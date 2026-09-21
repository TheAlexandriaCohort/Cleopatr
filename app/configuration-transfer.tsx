'use client';
import { useState } from 'react';
import { ArrowDownToLine, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  CONFIGURATION_MAX_BYTES,
  type ImportPreview,
} from '@/core/configuration';
import { api, download, Field } from './controls';

export default function ConfigurationTransfer({
  revision,
  onImported,
}: {
  revision: number;
  onImported: () => Promise<unknown>;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selected, setSelected] = useState<{
    configuration: unknown;
    preview: ImportPreview;
    name: string;
  } | null>(null);
  async function exportFile() {
    setBusy(true);
    setError('');
    try {
      download('cleopatr-configuration.json', await api('configuration'));
    } catch (e) {
      setError((e as Error).message);
      setOpen(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="configuration-actions">
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => void exportFile()}
        >
          <ArrowDownToLine size={15} />
          Export JSON
        </Button>
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => {
            setOpen(true);
            setError('');
            setNotice('');
            setSelected(null);
          }}
        >
          <Upload size={15} />
          Import JSON
        </Button>
      </div>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!busy) setOpen(next);
        }}
      >
        <DialogContent className="configuration-dialog">
          <DialogTitle>Import configuration</DialogTitle>
          <DialogDescription>
            Add or update policies, Environments, and resources from a Cleopatr
            JSON export. Matching IDs are updated; other objects are kept.
          </DialogDescription>
          <Field
            label="Configuration file"
            hint="JSON, up to 32 MiB. Credentials and activity cannot be imported here."
          >
            <Input
              type="file"
              accept=".json,application/json"
              disabled={busy}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                setSelected(null);
                setError('');
                setNotice('');
                if (!file) return;
                setBusy(true);
                try {
                  if (file.size >= CONFIGURATION_MAX_BYTES)
                    throw new Error('Choose a JSON file smaller than 32 MiB.');
                  const configuration: unknown = JSON.parse(await file.text());
                  const preview = await api<ImportPreview>(
                    'configuration/preview',
                    { configuration, revision },
                  );
                  setSelected({ configuration, preview, name: file.name });
                } catch (e) {
                  setError((e as Error).message);
                  if ((e as Error).message.includes('workspace changed'))
                    await onImported();
                } finally {
                  setBusy(false);
                  event.target.value = '';
                }
              }}
            />
          </Field>
          {selected && (
            <>
              <p>
                <strong>{selected.name}</strong>
              </p>
              <table className="import-summary">
                <thead>
                  <tr>
                    <th>Configuration</th>
                    <th>Add</th>
                    <th>Update</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(selected.preview.changes).map(
                    ([kind, counts]) => (
                      <tr key={kind}>
                        <th>{kind}</th>
                        <td>{counts.added}</td>
                        <td>{counts.updated}</td>
                      </tr>
                    ),
                  )}
                </tbody>
              </table>
              <p>
                Published policies, resource changes, assignments, and
                Environment modes take effect immediately. Drafts remain drafts.
                Existing published versions are retained when an imported policy
                has only a draft.
              </p>
              <p>
                Client access, signing keys, activity, and existing policy
                history are preserved.
              </p>
            </>
          )}
          {error && (
            <div className="error-box" role="alert">
              {error}
            </div>
          )}
          {notice && <output className="success-box">{notice}</output>}
          <div className="inline-actions">
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setOpen(false)}
            >
              Close
            </Button>
            <Button
              className="primary-button"
              disabled={busy || !selected}
              onClick={async () => {
                if (!selected) return;
                setBusy(true);
                setError('');
                try {
                  await api('configuration/import', {
                    configuration: selected.configuration,
                    revision: selected.preview.revision,
                  });
                  setSelected(null);
                  await onImported();
                  setNotice('Configuration imported.');
                } catch (e) {
                  setError((e as Error).message);
                  setSelected(null);
                  if ((e as Error).message.includes('workspace changed'))
                    await onImported();
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? 'Working…' : 'Import configuration'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

'use client';
import { useEffect, useState } from 'react';
import {
  Check as CheckIcon,
  ChevronRight,
  Copy,
  FileCode2,
  Layers3,
  LockKeyhole,
  Pencil,
  Plus,
  Search,
  Trash2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import DecisionTable from './decision-table';
import {
  ancestors,
  assignmentSnapshot,
  effectivePolicies,
  inheritedPolicies,
  summarizePolicyModes,
  policyResourceTypes,
  RESOURCE_TYPES,
  type Environment,
  type EnvironmentMode,
  type Policy,
} from '@/core/model';
import type { ApiInput, AppState, EventRecord } from '@/core/api-types';
import { api, Check, Picker } from './controls';

function Modes({
  value,
  options,
  onChange,
  disabled,
  disabledOptions = [],
  label,
}: {
  value: string;
  options: string[];
  onChange: (value: string) => void;
  disabled?: boolean;
  disabledOptions?: string[];
  label: string;
}) {
  return (
    <fieldset className="mode-switch" aria-label={label}>
      {options.map((mode) => (
        <button
          key={mode}
          type="button"
          disabled={disabled || disabledOptions.includes(mode)}
          aria-pressed={value === mode}
          title={
            mode === 'CUSTOM'
              ? 'Selected automatically when policies use different modes'
              : undefined
          }
          onClick={() => onChange(mode)}
        >
          {mode[0] + mode.slice(1).toLowerCase()}
        </button>
      ))}
    </fieldset>
  );
}
export default function EnvironmentPanel({
  state,
  onSaved,
  onEdit,
  onDelete,
  onPolicy,
}: {
  state: AppState;
  onSaved: () => Promise<unknown>;
  onEdit: (environment: Partial<Environment>) => void;
  onDelete: (environment: Environment) => void;
  onPolicy: (policy: Policy) => void;
}) {
  const [selected, setSelected] = useState(state.environments[0]?.id ?? '');
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [manage, setManage] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [activityEnv, setActivityEnv] = useState<string>();
  const [activityError, setActivityError] = useState('');
  const [loading, setLoading] = useState(true);
  const environment =
    state.environments.find((e) => e.id === selected) ?? state.environments[0];
  const id = environment?.id;
  const applicable = id ? effectivePolicies(assignmentSnapshot(state), id) : [];
  const aggregateMode = summarizePolicyModes(
    applicable,
    environment?.mode ?? 'AUDIT',
  );
  const inherited = new Map(
    (id ? inheritedPolicies(assignmentSnapshot(state), id) : []).map(
      (policy) => [policy.id, policy],
    ),
  );
  useEffect(() => {
    if (!id) return;
    let active = true;
    async function load() {
      try {
        const data = await api<EventRecord[]>(
          'environment-activity?environment=' + encodeURIComponent(id!),
        );
        if (active) {
          setEvents(data);
          setActivityError('');
        }
      } catch (e) {
        if (active) {
          setEvents([]);
          setActivityError((e as Error).message);
        }
      } finally {
        if (active) {
          setLoading(false);
          setActivityEnv(id);
        }
      }
    }
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [id, state.revision]);
  async function mutate(input: Partial<ApiInput>) {
    if (!id) return;
    setBusy(true);
    setError('');
    try {
      await api('mutate', {
        revision: state.revision,
        kind: 'environment',
        item: { id },
        ...input,
      });
      await onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function copyId() {
    try {
      await navigator.clipboard.writeText(id!);
      setCopied(true);
    } catch {
      setError(
        'Unable to copy automatically. Select and copy the environment ID below.',
      );
    }
  }
  function tree(parentId: string | null, depth = 0): React.ReactNode {
    return state.environments
      .filter((e) => e.parentId === parentId)
      .map((e) => {
        const children = state.environments.some((x) => x.parentId === e.id);
        const open = !collapsed.has(e.id);
        return (
          <div key={e.id}>
            <div
              className={'environment-node ' + (id === e.id ? 'selected' : '')}
              style={{ paddingLeft: 12 + depth * 18 }}
            >
              {children ? (
                <button
                  className="tree-expander"
                  aria-label={`${open ? 'Collapse' : 'Expand'} ${e.name}`}
                  aria-expanded={open}
                  onClick={() =>
                    setCollapsed((old) => {
                      const next = new Set(old);
                      if (next.has(e.id)) next.delete(e.id);
                      else next.add(e.id);
                      return next;
                    })
                  }
                >
                  <ChevronRight
                    size={15}
                    style={{ transform: open ? 'rotate(90deg)' : undefined }}
                  />
                </button>
              ) : (
                <span className="tree-spacer" />
              )}
              <button
                className="environment-select"
                aria-current={id === e.id ? 'true' : undefined}
                onClick={() => {
                  setSelected(e.id);
                  setError('');
                  setCopied(false);
                }}
              >
                <Layers3 size={17} />
                <span>
                  {e.name}
                  <small>
                    {e.kind === 'group' ? 'Environment group' : 'Environment'}
                  </small>
                </span>
              </button>
            </div>
            {children && open && tree(e.id, depth + 1)}
          </div>
        );
      });
  }
  if (!environment)
    return (
      <div className="empty">
        <h3>No environments yet</h3>
        <Button onClick={() => onEdit({})}>Add environment</Button>
      </div>
    );
  return (
    <div className="environment-layout">
      <aside className="surface environment-tree">
        <h2>Environments</h2>
        <nav aria-label="Environments">{tree(null)}</nav>
      </aside>
      <div className="environment-details">
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        <div className="surface detail-card environment-detail">
          <div className="environment-summary">
            <div>
              <span className="badge gold">
                {environment.kind === 'group'
                  ? 'Environment group'
                  : 'Environment'}
              </span>
              <h2>{environment.name}</h2>
              <div className="environment-id">
                <code>{id}</code>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Copy environment ID"
                  onClick={() => void copyId()}
                >
                  {copied ? <CheckIcon size={14} /> : <Copy size={14} />}
                </Button>
                {copied && <output>Copied</output>}
              </div>
            </div>
            <div className="environment-actions">
              <div className="inline-actions">
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Edit environment"
                  onClick={() => onEdit(environment)}
                >
                  <Pencil size={16} />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Delete environment"
                  onClick={() => onDelete(environment)}
                >
                  <Trash2 size={16} />
                </Button>
              </div>
              <Modes
                label="Environment policy mode"
                value={aggregateMode}
                options={['AUDIT', 'CUSTOM', 'ENFORCE']}
                disabled={busy}
                disabledOptions={['CUSTOM']}
                onChange={(mode) =>
                  void mutate({
                    operation: 'mode',
                    mode: mode as EnvironmentMode,
                  })
                }
              />
            </div>
          </div>
          <p>{environment.description}</p>
          <div className="inheritance-path">
            {ancestors(state.environments, environment.id)
              .reverse()
              .map((ancestorId, i) => (
                <span key={ancestorId}>
                  {i > 0 && <ChevronRight size={13} />}
                  {state.environments.find((e) => e.id === ancestorId)?.name}
                </span>
              ))}
          </div>
          <p className="help">
            Change any policy below. Audit and Enforce above apply to all
            editable policies; Custom appears automatically when modes differ.
            Inherited Enforce policies stay enforced.
          </p>
          <div className="mini-stats">
            <div>
              <strong>{applicable.length}</strong>
              <span>Assigned + inherited policies</span>
            </div>
            <div>
              <strong>
                {state.resources.filter((r) => r.environmentId === id).length}
              </strong>
              <span>Direct resources</span>
            </div>
          </div>
          <Button variant="outline" onClick={() => onEdit({ parentId: id })}>
            <Plus size={15} />
            Add child environment
          </Button>
        </div>
        <div className="section-bar spaced">
          <h2>Effective policies</h2>
          <Button variant="outline" onClick={() => setManage(true)}>
            Manage Policies
          </Button>
        </div>
        <div className="surface">
          {applicable.length ? (
            applicable.map((p) => (
              <div key={p.id} className="effective-policy effective-policy-row">
                <FileCode2 size={18} />
                <button
                  className="effective-policy-name row-link"
                  onClick={() =>
                    onPolicy(state.policies.find((x) => x.id === p.id)!)
                  }
                >
                  <strong>{p.name}</strong>
                  <small>
                    {p.sourceEnvironmentId === id
                      ? 'Assigned here'
                      : `Inherited from ${state.environments.find((e) => e.id === p.sourceEnvironmentId)?.name}`}{' '}
                    ·{' '}
                    {p.published
                      ? `Published v${p.published.version}${p.status === 'DRAFT' ? ' · draft changes saved' : ''}`
                      : 'Draft · not active on clients'}
                  </small>
                  {inherited.get(p.id)?.mode === 'ENFORCE' && (
                    <small>
                      <LockKeyhole size={12} aria-hidden="true" /> Enforce
                      required by parent
                    </small>
                  )}
                </button>
                <Modes
                  label={`Mode for ${p.name}`}
                  value={p.mode}
                  options={['AUDIT', 'ENFORCE']}
                  disabled={busy}
                  disabledOptions={
                    inherited.get(p.id)?.mode === 'ENFORCE' ? ['AUDIT'] : []
                  }
                  onChange={(mode) =>
                    void mutate({
                      operation: 'policy-mode',
                      policyId: p.id,
                      mode: mode as EnvironmentMode,
                    })
                  }
                />
              </div>
            ))
          ) : (
            <div className="empty">
              <h3>No effective policies</h3>
              <p>
                Use Manage Policies to assign policies here or inherit them from
                a parent.
              </p>
            </div>
          )}
        </div>
        <p className="help spaced">
          Only published policy versions reach clients. Updates are picked up by
          the next policy refresh.
        </p>
        <div className="section-bar spaced">
          <h2>Recent environment activity</h2>
          <span className="muted">Most recent 50 events</span>
        </div>
        <div className="surface">
          {activityEnv === id && activityError && (
            <p className="error-box" role="alert">
              {activityError}
            </p>
          )}
          <DecisionTable
            events={activityEnv === id ? events : []}
            environments={state.environments}
          />
          {(activityEnv !== id || !events.length) && (
            <div className="empty">
              <p>
                {loading || activityEnv !== id
                  ? 'Loading activity…'
                  : 'No policy events have been received for this environment.'}
              </p>
            </div>
          )}
        </div>
      </div>
      {manage && (
        <ManagePolicies
          state={state}
          environment={environment}
          onClose={() => setManage(false)}
          onSaved={onSaved}
        />
      )}
    </div>
  );
}
function ManagePolicies({
  state,
  environment,
  onClose,
  onSaved,
}: {
  state: AppState;
  environment: Environment;
  onClose: () => void;
  onSaved: () => Promise<unknown>;
}) {
  const inherited = new Map(
    inheritedPolicies(assignmentSnapshot(state), environment.id).map(
      (policy) => [policy.id, policy],
    ),
  );
  const [selected, setSelected] = useState(
    new Set(
      effectivePolicies(assignmentSnapshot(state), environment.id).map(
        (p) => p.id,
      ),
    ),
  );
  const [query, setQuery] = useState('');
  const [type, setType] = useState('all');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const policies = state.policies.filter(
    (p) =>
      p.name.toLowerCase().includes(query.trim().toLowerCase()) &&
      (type === 'all' || policyResourceTypes(p).some((t) => t === type)),
  );
  async function save() {
    setBusy(true);
    setError('');
    try {
      await api('mutate', {
        revision: state.revision,
        kind: 'environment',
        operation: 'policies',
        item: { id: environment.id },
        policyIds: [...new Set([...selected, ...inherited.keys()])],
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
      <DialogContent className="manage-policies-dialog">
        <DialogTitle>Manage policies · {environment.name}</DialogTitle>
        <DialogDescription>
          Choose policies to assign here. Inherited policies are required and
          can only be removed at their source environment. Drafts must be
          published before clients use them.
        </DialogDescription>
        <div className="filters">
          <div className="search-field">
            <Search size={15} />
            <Input
              aria-label="Search policies by name"
              placeholder="Search by policy name…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <Picker
            label="Resource type filter"
            value={type}
            onChange={setType}
            options={[
              { value: 'all', label: 'All resource types' },
              ...RESOURCE_TYPES.map((t) => ({ value: t, label: t })),
            ]}
          />
        </div>
        <div className="manage-policy-list">
          {policies.map((p) => (
            <div key={p.id} className="manage-policy-option">
              <Check
                checked={inherited.has(p.id) || selected.has(p.id)}
                disabled={busy || inherited.has(p.id)}
                onChange={(include) =>
                  setSelected((old) => {
                    const next = new Set(old);
                    if (include) next.add(p.id);
                    else next.delete(p.id);
                    return next;
                  })
                }
              >
                <strong>{p.name}</strong>
                <small>
                  {policyResourceTypes(p).join(', ')} ·{' '}
                  {p.published ? `Published v${p.published.version}` : 'Draft'}
                  {inherited.has(p.id) &&
                    ` · Inherited from ${state.environments.find((env) => env.id === inherited.get(p.id)!.sourceEnvironmentId)?.name ?? 'parent'} · Required`}
                </small>
              </Check>
            </div>
          ))}
          {!policies.length && <p className="empty">No matching policies.</p>}
        </div>
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        <div className="dialog-actions">
          <span className="help">{selected.size} policies selected</span>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={busy} onClick={() => void save()}>
            {busy ? 'Saving…' : 'Save policies'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

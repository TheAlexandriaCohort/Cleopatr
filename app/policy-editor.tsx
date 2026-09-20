'use client';
import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import {
  Code2,
  CheckCircle2,
  ShieldCheck,
  Sparkles,
  WandSparkles,
  Save,
} from 'lucide-react';
import {
  ACTIONS,
  CONTEXT_FIELDS,
  generateCedar,
  type Policy,
  type Snapshot,
  type Rule,
} from '@/core/model';
import type { ClientRecord } from '@/core/api-types';
import { api, Picker, Field, Check } from './controls';
const DEFAULT_RULE: Rule = {
  effect: 'permit',
  principal: '',
  action: 'file.read',
  resourceId: '',
  field: '',
  operator: 'equals',
  value: '',
};
const templates = [
  {
    id: 'read-db',
    name: 'Read-only database access',
    description: 'Allow SELECT; deny writes and unknown queries.',
    rule: {
      effect: 'permit',
      action: 'database.query',
      field: 'operation',
      operator: 'equals',
      value: 'SELECT',
    },
  },
  {
    id: 'no-delete',
    name: 'Protect production data',
    description: 'Forbid destructive database operations.',
    rule: {
      effect: 'forbid',
      action: 'database.query',
      field: 'operation',
      operator: 'in',
      value: 'INSERT,UPDATE,DELETE,DDL,COPY,CALL,UNKNOWN',
    },
  },
  {
    id: 'workspace',
    name: 'Keep writes in the workspace',
    description: 'Forbid writes when the adapter cannot confirm containment.',
    rule: {
      effect: 'forbid',
      action: 'file.write',
      field: 'withinWorkspace',
      operator: 'equals',
      value: 'false',
    },
  },
  {
    id: 'http-get',
    name: 'Allow read-only HTTP requests',
    description: 'Permit HTTP GET requests.',
    rule: {
      effect: 'permit',
      action: 'http.request',
      field: 'method',
      operator: 'equals',
      value: 'GET',
    },
  },
  {
    id: 'refund',
    name: 'Limit support refunds',
    description: 'Permit refunds below $500 (amount in whole dollars).',
    rule: {
      effect: 'permit',
      action: 'mcp.tool.invoke',
      field: 'amount',
      operator: 'lessThan',
      value: '500',
    },
  },
  {
    id: 'process',
    name: 'Allow an agent launcher',
    description: 'Permit an exact executable path.',
    rule: {
      effect: 'permit',
      action: 'process.execute',
      field: 'executable',
      operator: 'equals',
      value: '/usr/bin/python3',
    },
  },
];
export default function PolicyEditor({
  initial,
  snapshot,
  onClose,
  onSaved,
}: {
  initial: Policy | null;
  snapshot: Snapshot & { revision: number; clients: ClientRecord[] };
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [rule, setRule] = useState<Rule>(initial?.rule ?? DEFAULT_RULE);
  const [cedar, setCedar] = useState(
    initial?.cedar ?? generateCedar(DEFAULT_RULE, snapshot.resources),
  );
  const [scopes, setScopes] = useState(
    initial?.environmentIds ?? [snapshot.environments[0]?.id].filter(Boolean),
  );
  const [requirement, setRequirement] = useState(initial?.requirement ?? '');
  const [tab, setTab] = useState(
    initial && !initial.rule ? 'cedar' : 'builder',
  );
  const [validation, setValidation] = useState<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [manual, setManual] = useState(!!initial && !initial.rule);
  useEffect(() => {
    const timer = setTimeout(() => {
      api<{ valid: boolean; errors: string[]; warnings: string[] }>(
        'validate',
        { cedar },
      )
        .then(setValidation)
        .catch((e) =>
          setValidation({ valid: false, errors: [e.message], warnings: [] }),
        );
    }, 450);
    return () => clearTimeout(timer);
  }, [cedar]);
  function changeRule(patch: Partial<Rule>) {
    const next = { ...rule, ...patch };
    try {
      setCedar(generateCedar(next, snapshot.resources));
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
    setRule(next);
    setManual(false);
  }
  async function save(publish = false) {
    setBusy(true);
    setError('');
    try {
      await api('mutate', {
        revision: snapshot.revision,
        kind: 'policy',
        publish,
        item: {
          ...initial,
          name,
          description,
          cedar,
          environmentIds: scopes,
          requirement,
          ...(!manual ? { rule } : { rule: undefined }),
        },
      });
      await onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function draft() {
    setBusy(true);
    setError('');
    try {
      const result = await api<{ cedar: string }>('generate', { requirement });
      setCedar(result.cedar);
      setManual(true);
      setTab('cedar');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const resourceOptions = snapshot.resources
    .filter((r) => r.type === ACTIONS[rule.action])
    .map((r) => ({ value: r.id, label: r.name }));
  const principalNames = [
    ...new Set([
      ...snapshot.clients.map((client) => client.name),
      ...(rule.principal ? [rule.principal] : []),
    ]),
  ].sort((a, b) => a.localeCompare(b));
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="editor-dialog">
        <div className="dialog-heading">
          <span className="policy-icon">
            <ShieldCheck size={20} />
          </span>
          <div>
            <DialogTitle>
              {initial ? 'Edit policy' : 'Create a policy'}
            </DialogTitle>
            <DialogDescription>
              Build, review, and validate the boundaries for your agents.
            </DialogDescription>
          </div>
        </div>
        <div className="editor-layout">
          <div className="editor-main">
            <div className="form-grid">
              <Field label="Policy name">
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Protect production data"
                  maxLength={200}
                />
              </Field>
              <Field label="Description">
                <Input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What should this rule protect?"
                />
              </Field>
            </div>
            <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
              <TabsList className="editor-tabs">
                <TabsTrigger value="builder">
                  <WandSparkles size={15} />
                  Rule builder
                </TabsTrigger>
                <TabsTrigger value="cedar">
                  <Code2 size={15} />
                  Cedar editor
                </TabsTrigger>
                <TabsTrigger value="describe">
                  <Sparkles size={15} />
                  Describe a rule
                </TabsTrigger>
              </TabsList>
              <TabsContent value="builder">
                <div className="form-stack">
                  {manual && (
                    <p className="notice amber">
                      Editing the builder replaces your custom Cedar. Your
                      current Cedar remains available in the editor until you
                      change a field.
                    </p>
                  )}
                  <div className="form-grid">
                    <Field label="Effect">
                      <Picker
                        label="Effect"
                        value={rule.effect}
                        onChange={(v) =>
                          changeRule({ effect: v as Rule['effect'] })
                        }
                        options={[
                          { value: 'permit', label: 'Permit this action' },
                          { value: 'forbid', label: 'Forbid this action' },
                        ]}
                      />
                    </Field>
                    <Field label="Action">
                      <Picker
                        label="Action"
                        value={rule.action}
                        onChange={(v) =>
                          changeRule({ action: v, resourceId: '' })
                        }
                        options={Object.keys(ACTIONS).map((v) => ({
                          value: v,
                          label: v,
                        }))}
                      />
                    </Field>
                  </div>
                  <Field
                    label="Principal"
                    hint="Choose a saved client from Deploy, or apply this rule to every client."
                  >
                    <Picker
                      label="Principal"
                      value={rule.principal ?? ''}
                      onChange={(principal) => changeRule({ principal })}
                      options={[
                        { value: '', label: 'Any client (wildcard)' },
                        ...principalNames.map((name) => ({
                          value: name,
                          label: name,
                        })),
                      ]}
                    />
                  </Field>
                  <Field label="Resource">
                    <Picker
                      label="Resource"
                      value={rule.resourceId}
                      onChange={(v) => changeRule({ resourceId: v })}
                      options={[
                        { value: '', label: 'Any matching resource' },
                        ...resourceOptions,
                      ]}
                    />
                  </Field>
                  <div className="condition-box">
                    <h3>When these conditions apply</h3>
                    <div className="form-grid">
                      <Field label="Context field">
                        <Picker
                          label="Context field"
                          value={rule.field}
                          onChange={(v) => changeRule({ field: v })}
                          options={[
                            { value: '', label: 'Always' },
                            ...Object.entries(CONTEXT_FIELDS)
                              .filter(([, t]) => t !== 'Set')
                              .map(([v]) => ({ value: v, label: v })),
                          ]}
                        />
                      </Field>
                      {rule.field && (
                        <Field label="Comparison">
                          <Picker
                            label="Comparison"
                            value={rule.operator}
                            onChange={(v) =>
                              changeRule({ operator: v as Rule['operator'] })
                            }
                            options={[
                              { value: 'equals', label: 'Equals' },
                              { value: 'notEquals', label: 'Does not equal' },
                              {
                                value: 'in',
                                label: 'Is one of (comma-separated)',
                              },
                              { value: 'lessThan', label: 'Is less than' },
                            ]}
                          />
                        </Field>
                      )}
                    </div>
                    {rule.field && (
                      <Field
                        label="Value"
                        hint="If required facts are missing, a forbid still applies; a permit does not."
                      >
                        <Input
                          value={rule.value}
                          onChange={(e) =>
                            changeRule({ value: e.target.value })
                          }
                        />
                      </Field>
                    )}
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="cedar">
                <Field
                  label="Executable Cedar"
                  hint="Cedar is the canonical policy. Changes must pass schema validation."
                >
                  <Textarea
                    className="code-editor"
                    spellCheck={false}
                    value={cedar}
                    onChange={(e) => {
                      setCedar(e.target.value);
                      setManual(true);
                    }}
                  />
                </Field>
                <div className="code-hints">
                  Actions: {Object.keys(ACTIONS).join(' · ')}
                </div>
              </TabsContent>
              <TabsContent value="describe">
                <div className="form-stack">
                  <Field
                    label="What should this policy do?"
                    hint="AI drafts require a configured authoring provider. Every candidate must be validated and reviewed before publishing."
                  >
                    <Textarea
                      value={requirement}
                      onChange={(e) => setRequirement(e.target.value)}
                      placeholder="Agents may read the customer database, but must never delete customer records."
                      rows={5}
                    />
                  </Field>
                  <Button
                    variant="secondary"
                    disabled={busy || !requirement.trim()}
                    onClick={draft}
                  >
                    <Sparkles size={15} />
                    Generate a Cedar draft
                  </Button>
                  <p className="muted">
                    You can also save your requirement alongside a policy built
                    with the rule builder.
                  </p>
                </div>
              </TabsContent>
            </Tabs>
            <div className="cedar-preview">
              <div>
                <Code2 size={14} />
                <span>Cedar preview</span>
                <span
                  className={
                    'badge ' + (validation?.valid ? 'green' : 'neutral')
                  }
                >
                  {validation?.valid ? 'Valid' : 'Validating'}
                </span>
              </div>
              <pre>{cedar}</pre>
            </div>
            <p className="help">
              An unrestricted <code>principal</code> matches all cleo clients. A
              named client uses{' '}
              <code>Cleopatr::AgentSession::&quot;client-name&quot;</code>.
            </p>
            {validation && !validation.valid && (
              <div role="alert" className="error-box">
                {validation.errors.map((v, i) => (
                  <p key={i}>{v}</p>
                ))}
              </div>
            )}
            {validation?.warnings.map((w, i) => (
              <p className="notice amber" key={i}>
                {w}
              </p>
            ))}
          </div>
          <aside className="editor-aside">
            <h3>Apply to environments</h3>
            <p className="help">
              Child environments inherit assigned policies. Leave all unchecked
              to keep this policy unassigned.
            </p>
            <div className="scope-choices">
              {snapshot.environments.map((e) => (
                <Check
                  key={e.id}
                  checked={scopes.includes(e.id)}
                  onChange={(yes) =>
                    setScopes(
                      yes
                        ? [...scopes, e.id]
                        : scopes.filter((id) => id !== e.id),
                    )
                  }
                >
                  {e.name}
                  <small>
                    {e.kind === 'group'
                      ? 'Group · includes descendants'
                      : 'Environment'}
                  </small>
                </Check>
              ))}
            </div>
            <hr />
            <h3>Start with a template</h3>
            <div className="template-list">
              {templates.map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setName(t.name);
                    setDescription(t.description);
                    changeRule({ ...DEFAULT_RULE, ...t.rule } as Rule);
                    setTab('builder');
                  }}
                >
                  <strong>{t.name}</strong>
                  <small>{t.description}</small>
                </button>
              ))}
            </div>
          </aside>
        </div>
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        <div className="dialog-actions">
          <span className="help">
            <CheckCircle2 size={14} />
            Drafts keep the published version active.
          </span>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={busy || !name.trim() || !validation?.valid}
            onClick={() => void save()}
          >
            <Save size={15} />
            {busy ? 'Saving…' : 'Save draft'}
          </Button>
          <Button
            disabled={busy || !name.trim() || !validation?.valid}
            onClick={() => void save(true)}
          >
            Publish now
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

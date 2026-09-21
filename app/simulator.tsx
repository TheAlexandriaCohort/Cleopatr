'use client';
import { useRef, useState } from 'react';
import {
  ChevronDown,
  FileCode2,
  Layers3,
  Play,
  ShieldCheck,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
  PopoverTitle,
} from '@/components/ui/popover';
import {
  Command,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandItem,
} from '@/components/ui/command';
import { ACTIONS, type Policy } from '@/core/model';
import type { AppState, Simulation } from '@/core/api-types';
import { api, Field, Picker } from './controls';
type Choice = {
  value: string;
  id: string;
  name: string;
  description: string;
  source?: 'DRAFT' | 'PUBLISHED';
};
function policyChoices(policies: Policy[]): Choice[] {
  return policies.flatMap((policy) => [
    ...(policy.status !== 'PUBLISHED'
      ? [
          {
            value: 'DRAFT:' + policy.id,
            id: policy.id,
            name: policy.name,
            description: 'Draft',
            source: 'DRAFT' as const,
          },
        ]
      : []),
    ...(policy.published || policy.status === 'PUBLISHED'
      ? [
          {
            value: 'PUBLISHED:' + policy.id,
            id: policy.id,
            name: policy.published?.name ?? policy.name,
            description: `Published · v${policy.published?.version ?? policy.revision}`,
            source: 'PUBLISHED' as const,
          },
        ]
      : []),
  ]);
}
function ControlPicker({
  value,
  choices,
  kind,
  onChange,
}: {
  value: string;
  choices: Choice[];
  kind: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = choices.find((c) => c.value === value);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={<Button variant="outline" />}
        className="simulator-control-trigger"
        aria-label="Control"
      >
        <span>
          {selected ? (
            <>
              <strong>{selected.name}</strong>
              <small>{selected.description}</small>
            </>
          ) : (
            `Choose a ${kind.toLowerCase()}`
          )}
        </span>
        <ChevronDown size={16} />
      </PopoverTrigger>
      <PopoverContent align="start" className="simulator-control-menu">
        <PopoverTitle className="sr-only">
          Choose a {kind.toLowerCase()}
        </PopoverTitle>
        <Command defaultValue={value} label="Simulation control">
          <CommandInput
            aria-label="Search controls"
            placeholder={`Search ${kind === 'Policy' ? 'policies' : 'environments'}…`}
          />
          <CommandList>
            <CommandEmpty>
              No matching {kind === 'Policy' ? 'policies' : 'environments'}.
            </CommandEmpty>
            {choices.map((choice) => (
              <CommandItem
                key={choice.value}
                value={choice.value}
                keywords={[choice.name, choice.description]}
                data-checked={choice.value === value}
                onSelect={() => {
                  onChange(choice.value);
                  setOpen(false);
                }}
              >
                <span>
                  <strong>{choice.name}</strong>
                  <small>{choice.description}</small>
                </span>
              </CommandItem>
            ))}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
export default function Simulator({ state }: { state: AppState }) {
  const choices = policyChoices(state.policies);
  const [kind, setKind] = useState<'POLICY' | 'ENVIRONMENT'>('POLICY');
  const [policy, setPolicy] = useState(choices[0]?.value ?? '');
  const [environment, setEnvironment] = useState(
    state.environments[0]?.id ?? '',
  );
  const [principal, setPrincipal] = useState(state.clients[0]?.name ?? '');
  const [action, setAction] = useState('database.query');
  const [resource, setResource] = useState('customer-db');
  const [context, setContext] = useState(
    '{\n  "operation": "DELETE",\n  "tables": ["customers"],\n  "confidence": "semantic"\n}',
  );
  const [result, setResult] = useState<Simulation | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const requestVersion = useRef(0);
  const controls: Choice[] =
    kind === 'POLICY'
      ? choices
      : state.environments.map((e) => ({
          value: e.id,
          id: e.id,
          name: e.name,
          description: e.id,
        }));
  const value = kind === 'POLICY' ? policy : environment;
  const selected = controls.find((c) => c.value === value);
  function invalidate() {
    requestVersion.current++;
    setResult(null);
    setError('');
  }
  async function run() {
    if (!selected) return;
    const current = ++requestVersion.current;
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const response = await api<Simulation>('simulate', {
        controlType: kind,
        controlId: selected.id,
        source: selected.source,
        request: {
          environmentId: kind === 'ENVIRONMENT' ? selected.id : '',
          sessionId: 'simulation',
          principal: principal.trim(),
          action,
          resource: { type: ACTIONS[action], id: resource || 'unregistered' },
          context: JSON.parse(context),
        },
      });
      if (current === requestVersion.current) setResult(response);
    } catch (e) {
      if (current === requestVersion.current) setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="simulator-grid">
      <div className="surface detail-card">
        <div className="section-bar">
          <h2>Build an action</h2>
          <fieldset
            className="mode-switch simulator-mode-switch"
            aria-label="Simulation target"
          >
            <button
              type="button"
              aria-pressed={kind === 'POLICY'}
              onClick={() => {
                setKind('POLICY');
                invalidate();
              }}
            >
              <FileCode2 size={15} />
              Policy
            </button>
            <button
              type="button"
              aria-pressed={kind === 'ENVIRONMENT'}
              onClick={() => {
                setKind('ENVIRONMENT');
                invalidate();
              }}
            >
              <Layers3 size={15} />
              Environment
            </button>
          </fieldset>
        </div>
        <p className="help">
          {kind === 'POLICY'
            ? 'Test a draft or published policy on its own. A matching permit is required for Allow.'
            : 'Test published policies, inherited rules, and the selected environment’s policy modes.'}
        </p>
        <div className="form-stack spaced">
          <div className="field">
            <span>Control</span>
            <ControlPicker
              value={value}
              choices={controls}
              kind={kind === 'POLICY' ? 'Policy' : 'Environment'}
              onChange={(next) => {
                if (kind === 'POLICY') setPolicy(next);
                else setEnvironment(next);
                invalidate();
              }}
            />
          </div>
          <Field
            label="Principal"
            hint="Cleo client name. Names match exactly, including capitalization."
          >
            <Input
              value={principal}
              onChange={(e) => {
                setPrincipal(e.target.value);
                invalidate();
              }}
              placeholder="e.g. My agent"
              maxLength={200}
              list="simulator-principals"
            />
            <datalist id="simulator-principals">
              {[...new Set(state.clients.map((client) => client.name))].map(
                (name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ),
              )}
            </datalist>
          </Field>
          <Field label="Action">
            <Picker
              label="Simulation action"
              value={action}
              onChange={(next) => {
                setAction(next);
                setResource('');
                setContext('{}');
                invalidate();
              }}
              options={Object.keys(ACTIONS).map((value) => ({
                value,
                label: value,
              }))}
            />
          </Field>
          <Field label="Resource ID">
            <Input
              value={resource}
              onChange={(e) => {
                setResource(e.target.value);
                invalidate();
              }}
              placeholder="Catalog ID or observed resource"
              list="simulator-resource-ids"
            />
            <datalist id="simulator-resource-ids">
              {state.resources
                .filter((r) => r.type === ACTIONS[action])
                .map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
            </datalist>
          </Field>
          <Field
            label="Observed context (JSON)"
            hint="Only supply facts the adapter actually observes."
          >
            <Textarea
              className="code-editor"
              value={context}
              onChange={(e) => {
                setContext(e.target.value);
                invalidate();
              }}
              spellCheck={false}
            />
          </Field>
          <Button
            onClick={() => void run()}
            disabled={busy || !selected || !principal.trim()}
          >
            <Play size={16} />
            {busy ? 'Evaluating…' : 'Run simulation'}
          </Button>
        </div>
      </div>
      <div className="surface detail-card">
        {error ? (
          <div className="error-box" role="alert">
            {error}
          </div>
        ) : result ? (
          <>
            <div
              className={
                'decision ' + (result.decision === 'ALLOW' ? 'allow' : 'deny')
              }
            >
              <ShieldCheck size={34} />
              <div>
                <span>CEDAR DECISION</span>
                <strong>{result.decision}</strong>
              </div>
            </div>
            <p className="help spaced">
              {result.controlName} ·{' '}
              {result.source === 'PUBLISHED' ? 'Published' : 'Draft'} ·{' '}
              {result.policyCount}{' '}
              {result.policyCount === 1 ? 'policy' : 'policies'} ·{' '}
              {result.latencyUs} µs
              {result.controlType === 'ENVIRONMENT' && (
                <>
                  {' '}
                  · {result.mode} ·{' '}
                  {result.effectiveResult?.replaceAll('_', ' ')}
                </>
              )}
            </p>
            <p className="help">
              Principal: <strong>{result.parc.principal.id}</strong>
            </p>
            {result.controlType === 'POLICY' && (
              <p className="help">
                Environment context: {result.environmentName} (
                {result.contextSource}).
              </p>
            )}
            <h3 className="spaced">Determining policies</h3>
            {result.determiningPolicies.length ? (
              result.determiningPolicies.map((id) => (
                <p key={id} className="determining">
                  <FileCode2 size={16} />
                  {result.policyNames?.[id] ??
                    state.policies.find((p) => p.id === id)?.name ??
                    id}
                </p>
              ))
            ) : (
              <p className="help">
                No permit matched. Cedar denies by default.
              </p>
            )}
            {result.errors.length > 0 && (
              <div className="error-box">{result.errors.join('\n')}</div>
            )}
            <details className="spaced" open>
              <summary>
                Normalized principal / action / resource / context
              </summary>
              <pre className="json-block">
                {JSON.stringify(result.parc, null, 2)}
              </pre>
            </details>
            <div className="notice neutral spaced">
              This is a synthetic action. A real adapter must observe and supply
              these facts before enforcement.
            </div>
          </>
        ) : (
          <div className="empty">
            <ShieldCheck size={28} />
            <h3>A decision you can inspect</h3>
            <p>Select a control and enter a client name to test an action.</p>
          </div>
        )}
      </div>
    </div>
  );
}

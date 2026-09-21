'use client';
import { useEffect, useState } from 'react';
import Image from 'next/image';
import { useSearchParams } from 'next/navigation';
import {
  ShieldCheck,
  Layers3,
  Database,
  FileCode2,
  FlaskConical,
  Terminal,
  Activity,
  ArrowUpRight,
  Plus,
  ChevronRight,
  CircleDot,
  History,
  Search,
  RefreshCw,
  ArrowDownToLine,
  Pencil,
  Trash2,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import {
  SidebarProvider,
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarFooter,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from '@/components/ui/alert-dialog';
import { Skeleton } from '@/components/ui/skeleton';
import {
  RESOURCE_TYPES,
  ancestors,
  policiesFor,
  type Policy,
  type ResourceType,
} from '@/core/model';
import { api, download, Picker, Field } from './controls';
import PolicyEditor from './policy-editor';
import EnvironmentPanel from './environment-panel';
import ActivityPanel from './activity-panel';
import Simulator from './simulator';
import PolicyHistoryDialog from './policy-history';
import ConfigurationTransfer from './configuration-transfer';
import type {
  AppState as State,
  DraftItem,
  Enrollment,
} from '@/core/api-types';
const nav = [
  { icon: FileCode2, name: 'Policies' },
  { icon: Layers3, name: 'Environments' },
  { icon: Database, name: 'Resources' },
  { icon: FlaskConical, name: 'Simulator' },
  { icon: Activity, name: 'Activity' },
  { icon: Terminal, name: 'Deploy' },
];
const info: Record<
  string,
  [title: string, description: string, eyebrow: string]
> = {
  Policies: [
    'Rules for your agents.',
    'Create clear boundaries. Keep your agents moving.',
    'CREATE RULES',
  ],
  Environments: [
    'A place for every policy.',
    'Organize your environments. Let the right rules flow down.',
    'APPLY ORDER',
  ],
  Resources: [
    'Know what you’re protecting.',
    'Define the databases, tools, endpoints, and files your agents use.',
    'IDENTIFY ASSETS',
  ],
  Simulator: [
    'Test before you trust.',
    'Explore a decision using the same Cedar engine as the CLI.',
    'TEST CONTROLS',
  ],
  Activity: [
    'Every decision has a story.',
    'Review administrative changes and redacted client decisions.',
    'INSPECT BEHAVIOR',
  ],
  Deploy: [
    'Put your policies to work.',
    'Connect an agent to local authorization and signed policy updates.',
    'HARNESS AGENTS',
  ],
};
function Empty({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <Layers3 size={28} />
      <h3>{title}</h3>
      <p>{description}</p>
      {children}
    </div>
  );
}
function Effect({ cedar }: { cedar: string }) {
  const forbid = /\bforbid\s*\(/.test(cedar);
  return (
    <span className={'badge ' + (forbid ? 'red' : 'green')}>
      {forbid ? 'Forbid' : 'Permit'}
    </span>
  );
}
function Stamp({ value }: { value: string }) {
  return (
    <time dateTime={value}>
      {new Date(value).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
      })}
    </time>
  );
}
export default function Console({
  canSignOut = false,
}: {
  canSignOut?: boolean;
}) {
  const searchParams = useSearchParams();
  const page =
    nav.find(({ name }) => name.toLowerCase() === searchParams.get('page'))
      ?.name ?? 'Policies';
  const [state, setState] = useState<State | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [policy, setPolicy] = useState<Policy | null | undefined>(undefined);
  const [object, setObject] = useState<{
    kind: 'environment' | 'resource';
    item: DraftItem;
  } | null>(null);
  const [remove, setRemove] = useState<{
    kind: string;
    item: DraftItem;
  } | null>(null);
  const [historyPolicy, setHistoryPolicy] = useState<Policy | null>(null);
  async function refresh() {
    try {
      const s = await api<State>('state');
      setState(s);
      setError('');
      return s;
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    const timer = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(timer);
  }, []);
  async function task(fn: () => Promise<unknown>, message?: string) {
    setBusy(true);
    setError('');
    try {
      await fn();
      await refresh();
      if (message) setNotice(message);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function go(value: string) {
    if (value !== page) {
      const url = new URL(window.location.href);
      url.searchParams.set('page', value.toLowerCase());
      window.history.pushState(null, '', url);
    }
    setQuery('');
    setFilter('all');
    setNotice('');
  }
  const publishedCount = state?.policies.filter((p) => p.published).length ?? 0;
  const envOptions =
    state?.environments.map((e) => ({ value: e.id, label: e.name })) ?? [];
  const policies =
    state?.policies.filter(
      (p) =>
        (filter === 'all' ||
          policiesFor(state, filter).some((x) => x.id === p.id)) &&
        (p.name + ' ' + p.description + ' ' + p.cedar)
          .toLowerCase()
          .includes(query.toLowerCase()),
    ) ?? [];
  return (
    <SidebarProvider
      style={{ '--sidebar-width': '232px' } as React.CSSProperties}
    >
      <Sidebar className="cleo-sidebar">
        <SidebarHeader>
          <div className="brand">
            <Image
              unoptimized
              className="brand-logo"
              src="/brand/cleopatr-logo.png"
              alt="cleopatr"
              width={509}
              height={494}
            />
          </div>
          <div className="workspace">
            <span className="workspace-icon">
              <Image
                unoptimized
                src="/brand/cleopatr-feather.png"
                alt=""
                width={264}
                height={376}
                style={{ width: 20, height: 'auto' }}
              />
            </span>
            <div>
              My organization<small>Policy workspace</small>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <div className="nav-label">CONTROL PLANE</div>
          {nav.map(({ icon: Icon, name }) => (
            <button
              className={'nav-item ' + (page === name ? 'active' : '')}
              onClick={() => go(name)}
              key={name}
              aria-current={page === name ? 'page' : undefined}
            >
              <Icon size={18} />
              <span className="nav-title">{name}</span>
              {name === 'Policies' && state && (
                <span className="nav-count">{state.policies.length}</span>
              )}
            </button>
          ))}
        </SidebarContent>
        <SidebarFooter>
          {state && (
            <ConfigurationTransfer
              revision={state.revision}
              onImported={refresh}
            />
          )}
          <div className="sidebar-note">
            <CircleDot size={15} />
            <span>Local decisions. Central control.</span>
          </div>
          <div className="profile">
            <span className="avatar">YO</span>
            <div>
              Your workspace<small>Private access</small>
            </div>
          </div>
          {canSignOut && (
            <Button
              variant="ghost"
              onClick={async () => {
                const response = await fetch('/api/session', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ logout: true }),
                });
                if (response.ok) window.location.assign('/login');
              }}
            >
              Sign out
            </Button>
          )}
        </SidebarFooter>
      </Sidebar>
      <div className="main-shell">
        <header className="topbar">
          <div>
            <SidebarTrigger />
            <Image
              unoptimized
              className="topbar-brand"
              src="/brand/cleopatr-feather.png"
              alt="cleopatr"
              width={264}
              height={376}
            />
            <span>Workspace</span>
            <ChevronRight size={15} />
            <strong>{page}</strong>
          </div>
          <span className="top-status">
            <span />
            {`${publishedCount} published policies`}
          </span>
        </header>
        <main className="page-content">
          <div className="eyebrow">{info[page][2]}</div>
          <div className="page-title">
            <div>
              <h1>{info[page][0]}</h1>
              <p>{info[page][1]}</p>
            </div>
            <div className="inline-actions">
              {['Policies', 'Environments', 'Resources'].includes(page) && (
                <Button
                  className="primary-button"
                  disabled={!state}
                  onClick={() =>
                    page === 'Policies'
                      ? setPolicy(null)
                      : setObject({
                          kind:
                            page === 'Environments'
                              ? 'environment'
                              : 'resource',
                          item: {},
                        })
                  }
                >
                  <Plus size={17} />
                  {page === 'Policies'
                    ? 'Create policy'
                    : page === 'Environments'
                      ? 'Add environment'
                      : 'Add resource'}
                </Button>
              )}
              <Button
                variant="ghost"
                size="icon"
                aria-label="Refresh workspace"
                disabled={busy}
                onClick={() => void refresh()}
              >
                <RefreshCw size={16} />
              </Button>
            </div>
          </div>
          {error && (
            <div className="error-box" role="alert">
              <AlertCircle size={18} />
              <span>{error}</span>
              <Button variant="outline" onClick={() => void refresh()}>
                Retry
              </Button>
            </div>
          )}
          {notice && (
            <output className="success-box">
              <CheckCircle2 size={17} />
              {notice}
              <button aria-label="Dismiss" onClick={() => setNotice('')}>
                ×
              </button>
            </output>
          )}
          {!state ? (
            <div className="loading">
              <Skeleton className="h-28 w-full" />
              <Skeleton className="h-80 w-full" />
            </div>
          ) : (
            <>
              {page === 'Policies' && (
                <>
                  <div className="stats">
                    <div>
                      <span>POLICIES</span>
                      <strong>
                        {state.policies.length}
                        <small>{publishedCount} published</small>
                      </strong>
                    </div>
                    <div>
                      <span>ENVIRONMENTS</span>
                      <strong>
                        {state.environments.length}
                        <small>with inherited rules</small>
                      </strong>
                    </div>
                    <div>
                      <span>RESOURCES</span>
                      <strong>
                        {state.resources.length}
                        <small>in your catalog</small>
                      </strong>
                    </div>
                    <div>
                      <span>DRAFTS</span>
                      <strong>
                        {
                          state.policies.filter((p) => p.status !== 'PUBLISHED')
                            .length
                        }
                        <small>ready to review and publish</small>
                      </strong>
                    </div>
                  </div>
                  <div className="section-bar">
                    <h2>
                      Policy library <span>{policies.length}</span>
                    </h2>
                    <div className="filters">
                      <div className="search-field">
                        <Search size={15} />
                        <Input
                          aria-label="Search policies"
                          placeholder="Search policies…"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                        />
                      </div>
                      <Picker
                        label="Environment filter"
                        value={filter}
                        onChange={setFilter}
                        options={[
                          { value: 'all', label: 'All environments' },
                          ...envOptions,
                        ]}
                      />
                    </div>
                  </div>
                  <div className="surface">
                    {policies.length ? (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>POLICY</TableHead>
                            <TableHead>EFFECT</TableHead>
                            <TableHead>ENVIRONMENT</TableHead>
                            <TableHead>STATUS</TableHead>
                            <TableHead />
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {policies.map((p) => (
                            <TableRow key={p.id}>
                              <TableCell>
                                <button
                                  className="policy-name row-link"
                                  onClick={() => setPolicy(p)}
                                >
                                  <span className="policy-icon">
                                    <FileCode2 size={20} />
                                  </span>
                                  <div>
                                    <strong>{p.name}</strong>
                                    <small>
                                      {p.description ||
                                        `Revision ${p.revision}`}
                                    </small>
                                  </div>
                                </button>
                              </TableCell>
                              <TableCell>
                                <Effect cedar={p.cedar} />
                              </TableCell>
                              <TableCell>
                                <span className="scope">
                                  <Layers3 size={14} />
                                  {p.environmentIds
                                    .map(
                                      (id) =>
                                        state.environments.find(
                                          (e) => e.id === id,
                                        )?.name,
                                    )
                                    .join(', ')}
                                </span>
                              </TableCell>
                              <TableCell>
                                <span
                                  className={
                                    'badge ' +
                                    (p.status === 'PUBLISHED'
                                      ? 'gold'
                                      : 'neutral')
                                  }
                                >
                                  {p.status === 'PUBLISHED'
                                    ? 'Published'
                                    : 'Draft'}
                                </span>
                                {p.published && (
                                  <small className="block muted mt-1">
                                    v{p.published.version} active
                                  </small>
                                )}
                              </TableCell>
                              <TableCell>
                                <div className="inline-actions">
                                  {p.status !== 'PUBLISHED' && (
                                    <Button
                                      variant="outline"
                                      disabled={busy}
                                      onClick={() =>
                                        void task(
                                          () =>
                                            api('mutate', {
                                              revision: state.revision,
                                              kind: 'policy',
                                              operation: 'publish',
                                              item: { id: p.id },
                                            }),
                                          'Policy published. Clients receive it on their next refresh.',
                                        )
                                      }
                                    >
                                      Publish
                                    </Button>
                                  )}
                                  <Button
                                    variant="ghost"
                                    size="icon-sm"
                                    aria-label={`Version history for ${p.name}`}
                                    onClick={() => setHistoryPolicy(p)}
                                  >
                                    <History size={16} />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="icon-sm"
                                    aria-label={`Edit ${p.name}`}
                                    onClick={() => setPolicy(p)}
                                  >
                                    <ArrowUpRight size={17} />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="icon-sm"
                                    aria-label={`Delete ${p.name}`}
                                    onClick={() =>
                                      setRemove({ kind: 'policy', item: p })
                                    }
                                  >
                                    <Trash2 size={14} />
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    ) : (
                      <Empty
                        title="No policies found"
                        description="Create a policy or try a different search."
                      />
                    )}
                  </div>
                  <div className="bottom-grid">
                    <div className="guide-card">
                      <div className="guide-icon">
                        <Layers3 />
                      </div>
                      <div>
                        <h3>One rule. Every environment.</h3>
                        <p>
                          Assign a policy to a parent environment to apply it
                          across every child. Specific forbids always take
                          precedence.
                        </p>
                        <button
                          className="text-link"
                          onClick={() => go('Environments')}
                        >
                          Explore environments <ArrowUpRight size={15} />
                        </button>
                      </div>
                    </div>
                    <div className="terminal-card">
                      <div>
                        <Terminal size={17} />
                        <span>Bring your agent under policy</span>
                      </div>
                      <code>
                        <span>$</span> cleo | your-agent
                      </code>
                      <small>
                        Enable once in zsh: eval &quot;$(cleo init zsh)&quot;
                      </small>
                      <button
                        className="text-link light"
                        onClick={() => go('Deploy')}
                      >
                        Connect your CLI <ArrowUpRight size={15} />
                      </button>
                    </div>
                  </div>
                </>
              )}
              {page === 'Environments' && (
                <EnvironmentPanel
                  state={state}
                  onSaved={refresh}
                  onEdit={(item) => setObject({ kind: 'environment', item })}
                  onDelete={(item) => setRemove({ kind: 'environment', item })}
                  onPolicy={setPolicy}
                />
              )}
              {page === 'Resources' && (
                <>
                  <div className="section-bar">
                    <h2>
                      Resource catalog <span>{state.resources.length}</span>
                    </h2>
                    <div className="filters">
                      <div className="search-field">
                        <Search size={15} />
                        <Input
                          aria-label="Search resources"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                          placeholder="Search resources…"
                        />
                      </div>
                      <Picker
                        label="Resource environment"
                        value={filter}
                        onChange={setFilter}
                        options={[
                          { value: 'all', label: 'All environments' },
                          ...envOptions,
                        ]}
                      />
                    </div>
                  </div>
                  <div className="surface">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>RESOURCE</TableHead>
                          <TableHead>TYPE</TableHead>
                          <TableHead>ENVIRONMENT</TableHead>
                          <TableHead />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {state.resources
                          .filter(
                            (r) =>
                              (filter === 'all' ||
                                r.environmentId === filter) &&
                              (r.name + ' ' + r.locator)
                                .toLowerCase()
                                .includes(query.toLowerCase()),
                          )
                          .map((r) => (
                            <TableRow key={r.id}>
                              <TableCell>
                                <button
                                  className="policy-name row-link"
                                  onClick={() =>
                                    setObject({ kind: 'resource', item: r })
                                  }
                                >
                                  <span className="policy-icon">
                                    <Database size={19} />
                                  </span>
                                  <div>
                                    <strong>{r.name}</strong>
                                    <small className="mono">{r.locator}</small>
                                  </div>
                                </button>
                              </TableCell>
                              <TableCell>
                                <span className="badge neutral">{r.type}</span>
                              </TableCell>
                              <TableCell>
                                <span className="scope">
                                  <Layers3 size={14} />
                                  {
                                    state.environments.find(
                                      (e) => e.id === r.environmentId,
                                    )?.name
                                  }
                                </span>
                              </TableCell>
                              <TableCell>
                                <div className="inline-actions">
                                  <Button
                                    variant="ghost"
                                    size="icon-sm"
                                    aria-label={`Edit ${r.name}`}
                                    onClick={() =>
                                      setObject({ kind: 'resource', item: r })
                                    }
                                  >
                                    <Pencil size={15} />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="icon-sm"
                                    aria-label={`Delete ${r.name}`}
                                    onClick={() =>
                                      setRemove({ kind: 'resource', item: r })
                                    }
                                  >
                                    <Trash2 size={15} />
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                      </TableBody>
                    </Table>
                    {!state.resources.length && (
                      <Empty
                        title="No resources yet"
                        description="Add a database, file path, endpoint, process, or MCP tool."
                      />
                    )}
                  </div>
                  <p className="help spaced">
                    Catalog entries describe policy subjects. Adding a resource
                    does not connect to or modify the underlying system.
                  </p>
                </>
              )}
              {page === 'Simulator' && <Simulator state={state} />}
              {page === 'Activity' && <ActivityPanel state={state} />}
              {page === 'Deploy' && (
                <Connect state={state} refresh={refresh} task={task} />
              )}
            </>
          )}
          <footer className="page-footer">
            <ShieldCheck size={14} /> Powered by Cedar
            {state ? ` ${state.engine}` : ''}. Decisions you can explain.
          </footer>
        </main>
      </div>
      {state && policy !== undefined && (
        <PolicyEditor
          initial={policy}
          snapshot={state}
          onClose={() => setPolicy(undefined)}
          onSaved={async () => {
            await refresh();
            setNotice(
              'Policy saved. Published versions reach clients on their next refresh.',
            );
          }}
        />
      )}
      {state && object && (
        <ObjectEditor
          value={object}
          state={state}
          onClose={() => setObject(null)}
          onSaved={async () => {
            await refresh();
            setNotice('Saved. This change is immediately available.');
          }}
        />
      )}
      {state && historyPolicy && (
        <PolicyHistoryDialog
          policy={historyPolicy}
          revision={state.revision}
          onClose={() => setHistoryPolicy(null)}
          onSaved={refresh}
        />
      )}
      <AlertDialog
        open={!!remove}
        onOpenChange={(open) => !open && setRemove(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {remove?.item.name}?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes it from the workspace and future client policy
              updates. Clients using a cached policy set will see the change on
              their next refresh.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                void task(async () => {
                  await api('mutate', {
                    revision: state!.revision,
                    kind: remove!.kind,
                    operation: 'delete',
                    item: remove!.item,
                  });
                  setRemove(null);
                }, 'Removed from the workspace.')
              }
            >
              Delete item
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </SidebarProvider>
  );
}
const resourceLocatorHints: Record<
  ResourceType,
  { placeholder: string; hint: string }
> = {
  Database: {
    placeholder: 'postgresql://db.internal/customers',
    hint: 'A PostgreSQL or MySQL connection URI. Do not include credentials.',
  },
  File: {
    placeholder: '/workspace/data',
    hint: 'An absolute directory path accessible to the agent.',
  },
  Endpoint: {
    placeholder: 'https://api.example.com/v1',
    hint: 'An HTTP(S) URL with an optional path. Do not include credentials or query parameters.',
  },
  MCPTool: {
    placeholder: 'https://mcp.example.com/mcp#search',
    hint: 'An MCP HTTP(S) transport URL; append #tool-name to identify a specific tool. Do not include credentials.',
  },
  Process: {
    placeholder: '/usr/bin/node',
    hint: 'An absolute path to the executable, interpreter, or tool.',
  },
  Network: {
    placeholder: 'tcp://api.example.com:443',
    hint: 'A TCP/UDP host and port, HTTP(S) origin, or DNS locator such as dns://example.com.',
  },
};

function ObjectEditor({
  value,
  state,
  onClose,
  onSaved,
}: {
  value: { kind: 'environment' | 'resource'; item: DraftItem };
  state: State;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const isEnv = value.kind === 'environment';
  const [item, setItem] = useState({
    name: '',
    description: '',
    kind: 'environment',
    parentId: 'organization',
    environmentId: 'development',
    type: 'Database',
    locator: '',
    ...value.item,
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const locatorHint =
    resourceLocatorHints[item.type as ResourceType] ??
    resourceLocatorHints.Database;
  const patch = (v: Partial<typeof item>) => setItem({ ...item, ...v });
  async function save() {
    setBusy(true);
    setError('');
    try {
      await api('mutate', { revision: state.revision, kind: value.kind, item });
      await onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="object-dialog">
        <DialogTitle>
          {item.id ? 'Edit' : 'Add'} {isEnv ? 'environment' : 'resource'}
        </DialogTitle>
        <DialogDescription>
          {isEnv
            ? 'Policies flow from parent groups into every descendant.'
            : 'Use a stable catalog entry as the subject of your policies.'}
        </DialogDescription>
        <div className="form-stack">
          <Field label="Name">
            <Input
              value={item.name}
              onChange={(e) => patch({ name: e.target.value })}
            />
          </Field>
          <Field label="Description">
            <Textarea
              value={item.description}
              onChange={(e) => patch({ description: e.target.value })}
            />
          </Field>
          {isEnv ? (
            <>
              <Field label="Type">
                <Picker
                  label="Environment type"
                  value={item.kind}
                  onChange={(v) => patch({ kind: v })}
                  options={[
                    { value: 'environment', label: 'Environment' },
                    { value: 'group', label: 'Environment group' },
                  ]}
                />
              </Field>
              <Field label="Parent">
                <Picker
                  label="Parent environment"
                  value={item.parentId ?? ''}
                  onChange={(v) => patch({ parentId: v || null })}
                  options={[
                    { value: '', label: 'No parent (top level)' },
                    ...state.environments
                      .filter(
                        (e) =>
                          !item.id ||
                          !ancestors(state.environments, e.id).includes(
                            item.id,
                          ),
                      )
                      .map((e) => ({ value: e.id, label: e.name })),
                  ]}
                />
              </Field>
            </>
          ) : (
            <>
              <Field label="Resource type">
                <Picker
                  label="Resource type"
                  value={item.type}
                  onChange={(v) => patch({ type: v })}
                  options={RESOURCE_TYPES.map((v) => ({ value: v, label: v }))}
                />
              </Field>
              <Field label="Environment">
                <Picker
                  label="Resource environment"
                  value={item.environmentId}
                  onChange={(v) => patch({ environmentId: v })}
                  options={state.environments.map((e) => ({
                    value: e.id,
                    label: e.name,
                  }))}
                />
              </Field>
              <Field label="Locator" hint={locatorHint.hint}>
                <Input
                  value={item.locator}
                  onChange={(e) => patch({ locator: e.target.value })}
                  placeholder={locatorHint.placeholder}
                />
              </Field>
            </>
          )}
        </div>
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        <div className="dialog-actions">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={busy || !item.name.trim()} onClick={save}>
            Save {isEnv ? 'environment' : 'resource'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
function Connect({
  state,
  refresh,
  task,
}: {
  state: State;
  refresh: () => Promise<State | undefined>;
  task: (fn: () => Promise<unknown>, message?: string) => Promise<void>;
}) {
  const [name, setName] = useState('My agent');
  const [environment, setEnvironment] = useState(
    state.environments[0]?.id ?? '',
  );
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [expiration, setExpiration] = useState('never');
  const [expiresAt, setExpiresAt] = useState('');
  const [clientSearch, setClientSearch] = useState('');
  const [bundleClientId, setBundleClientId] = useState('');
  const [downloadingBundle, setDownloadingBundle] = useState(false);
  const [clientStatusTime, setClientStatusTime] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setClientStatusTime(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);
  const visibleClients = state.clients.filter((client) =>
    `${client.name} ${client.id}`
      .toLowerCase()
      .includes(clientSearch.toLowerCase()),
  );
  const nameExists = state.clients.some(
    (client) => client.name === name.trim(),
  );
  const bundleClients = state.clients.filter(
    (client) =>
      !client.revoked &&
      (!client.expires_at || Date.parse(client.expires_at) > clientStatusTime),
  );
  const bundleClient = bundleClients.find(
    (client) => client.id === bundleClientId,
  );
  async function enroll() {
    if (nameExists) return;
    setBusy(true);
    setError('');
    try {
      const r = await api<Enrollment>('enroll', {
        name,
        environmentIds: [environment],
        expiresAt:
          expiration === 'never' ? null : new Date(expiresAt).toISOString(),
      });
      setEnrollment({
        ...r,
        server: location.origin,
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="connect-grid">
        <div className="surface detail-card">
          <span className="step-number">01</span>
          <h2>Install the CLI</h2>
          <p>
            Node.js 22.13 or later is required. On Apple Silicon, start Docker
            Desktop before launching an agent.
          </p>
          <a
            className="download-link"
            href="/downloads/cleopatr-cli-0.6.1.tgz"
            download
          >
            <ArrowDownToLine size={17} />
            Download Cleopatr CLI
          </a>
          <pre className="install-command">
            npm install -g ./cleopatr-cli-0.6.1.tgz
          </pre>
          <div className="capability-note">
            <ShieldCheck size={18} />
            <p>
              Protected launch now uses a Linux VM on Apple Silicon or a
              configured native Linux supervisor. Filesystem, process and
              network isolation remains active. HTTPS tunnels pass through in
              audit-only sessions. Full HTTPS inspection and database protocol
              adapters remain unavailable.
            </p>
          </div>
        </div>
        <div className="surface detail-card">
          <span className="step-number">02</span>
          <h2>Enroll your client</h2>
          <p>
            Credentials are scoped to the selected environment and its
            descendants.
          </p>
          <div className="form-stack spaced">
            <Field
              label="Client name"
              hint="Unique within this workspace. Names are case-sensitive."
            >
              <Input
                value={name}
                maxLength={200}
                aria-invalid={nameExists}
                aria-describedby={nameExists ? 'client-name-error' : undefined}
                onChange={(e) => {
                  setName(e.target.value);
                  setError('');
                }}
              />
            </Field>
            {nameExists && (
              <p className="error-box" id="client-name-error" role="alert">
                Client name already exists in this workspace. Choose a different
                name.
              </p>
            )}
            <Field label="Environment or group">
              <Picker
                label="Client environment"
                value={environment}
                onChange={setEnvironment}
                options={state.environments.map((e) => ({
                  value: e.id,
                  label: e.name,
                }))}
              />
            </Field>
            <Field label="Access expiration">
              <Picker
                label="Access expiration"
                value={expiration}
                onChange={setExpiration}
                options={[
                  { value: 'never', label: 'Never' },
                  { value: 'scheduled', label: 'Set a date and time' },
                ]}
              />
            </Field>
            {expiration === 'scheduled' && (
              <Field label="Expires at" hint="Uses your local time zone.">
                <Input
                  type="datetime-local"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                />
              </Field>
            )}
            <Button
              onClick={enroll}
              disabled={
                busy ||
                nameExists ||
                !environment ||
                !name.trim() ||
                (expiration === 'scheduled' && !expiresAt)
              }
            >
              <Plus size={16} />
              Create client credential
            </Button>
          </div>
          {error && <p className="error-box">{error}</p>}
          {enrollment && (
            <div className="enrollment-result">
              <CheckCircle2 size={20} />
              <strong>Client ready</strong>
              <p>
                Save this credential now. The client record is saved; the
                credential is only available to download here.{' '}
                {enrollment.expiresAt
                  ? `Access expires ${new Date(enrollment.expiresAt).toLocaleString()}.`
                  : 'Access does not expire unless revoked.'}
              </p>
              <Button
                onClick={() => download('cleopatr-enrollment.json', enrollment)}
              >
                <ArrowDownToLine size={16} />
                Download enrollment
              </Button>
            </div>
          )}
        </div>
      </div>
      <div className="terminal-card spaced">
        <div>
          <Terminal size={18} />
          <span>03 · Launch your agent</span>
        </div>
        <pre>{`cleo enroll --config ./cleopatr-enrollment.json\ncleo sync\n\n# Enable pipe-style launch in interactive zsh\neval "$(cleo init zsh)"\ncleo | your-agent\ncleo --env=Development | tests/curl-agent.js\n\n# Audit-only policies, keeping the enclave\ncleo --audit --env=Development | tests/curl-agent.js\n\n# Scripts and other shells\ncleo --env=Development -- tests/curl-agent.js\n\n# Authorize an explicit adapter action\ncleo authorize --request action.json`}</pre>
        <small>
          Decisions use a verified local bundle immediately. A background
          refresh starts when it has not been checked for five minutes; outages
          retain the last known policies. Set &quot;environment&quot; in
          .cleo/config or use --env with an environment ID or name.
        </small>
      </div>
      <div className="notice amber spaced">
        Pipe-style launch requires the interactive zsh hook. Without it, the
        shell starts the agent independently. Protected launch requires
        published permissions for the agent executables and runtime reads; a
        network forbid alone does not permit startup. Environment names must
        exist in your assigned signed bundle. The bundled VM runs Linux
        Node/curl workloads; other tools need a provisioned Linux runtime.
      </div>
      <div className="notice neutral spaced">
        Enrolled clients connect directly to this server using their own
        credentials. Keep the server URL reachable from your agents. You can
        also download a signed bundle below for offline use.
      </div>
      <div className="section-bar spaced">
        <h2>Offline bundle</h2>
      </div>
      <div className="surface detail-card">
        <Field
          label="Client"
          hint="Includes published policies for this client’s assigned Environments and their inherited policies."
        >
          <Picker
            label="Offline bundle client"
            value={bundleClient?.id ?? ''}
            onChange={setBundleClientId}
            options={[
              { value: '', label: 'Select a client' },
              ...bundleClients.map((client) => ({
                value: client.id,
                label:
                  bundleClients.filter((other) => other.name === client.name)
                    .length > 1
                    ? `${client.name} (${client.id})`
                    : client.name,
              })),
            ]}
          />
        </Field>
        {!bundleClients.length && (
          <p>Create an active client to download an offline bundle.</p>
        )}
        <Button
          className="spaced"
          variant="outline"
          disabled={!bundleClient || downloadingBundle}
          onClick={async () => {
            if (!bundleClient) return;
            setDownloadingBundle(true);
            try {
              await task(async () => {
                const bundle = await api(
                  'bundles?clientId=' + encodeURIComponent(bundleClient.id),
                );
                download('cleopatr-bundle.json', bundle);
              }, `Signed bundle for ${bundleClient.name} downloaded. Import it with cleo import --file cleopatr-bundle.json.`);
            } finally {
              setDownloadingBundle(false);
            }
          }}
        >
          <ArrowDownToLine size={16} />
          Download signed bundle
        </Button>
      </div>
      <div className="section-bar spaced">
        <h2>
          Enrolled clients <span>{state.clients.length}</span>
        </h2>
        <Input
          aria-label="Search enrolled clients"
          placeholder="Search clients…"
          value={clientSearch}
          onChange={(e) => setClientSearch(e.target.value)}
          className="client-search"
        />
      </div>
      <div className="surface">
        {visibleClients.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CLIENT</TableHead>
                <TableHead>CREATED</TableHead>
                <TableHead>LAST CHECK-IN</TableHead>
                <TableHead>EXPIRES</TableHead>
                <TableHead>STATUS</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {visibleClients.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    {c.name}
                    <small className="block muted">
                      {JSON.parse(c.environment_ids)
                        .map(
                          (id: string) =>
                            state.environments.find((e) => e.id === id)?.name ??
                            id,
                        )
                        .join(', ')}
                    </small>
                  </TableCell>
                  <TableCell>
                    <Stamp value={c.created_at} />
                  </TableCell>
                  <TableCell>
                    {c.last_seen ? (
                      <Stamp value={c.last_seen} />
                    ) : (
                      'Not connected'
                    )}
                  </TableCell>
                  <TableCell>
                    {c.expires_at ? <Stamp value={c.expires_at} /> : 'Never'}
                  </TableCell>
                  <TableCell>
                    <span
                      className={
                        'badge ' +
                        (c.revoked ||
                        (c.expires_at &&
                          Date.parse(c.expires_at) <= clientStatusTime)
                          ? 'neutral'
                          : 'green')
                      }
                    >
                      {c.revoked
                        ? 'Revoked'
                        : c.expires_at &&
                            Date.parse(c.expires_at) <= clientStatusTime
                          ? 'Expired'
                          : 'Active'}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      disabled={!!c.revoked}
                      onClick={() =>
                        void task(async () => {
                          await api('revoke', { id: c.id });
                        }, 'Client credential revoked.')
                      }
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty
            title={
              state.clients.length
                ? 'No matching clients'
                : 'No clients enrolled'
            }
            description={
              state.clients.length
                ? 'Try another client name.'
                : 'Create your first client credential above.'
            }
          />
        )}
      </div>
    </>
  );
}

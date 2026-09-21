'use client';
import { useEffect, useRef, useState } from 'react';
import { CalendarDays, ChevronDown, RefreshCw, Search, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
  PopoverTitle,
  PopoverDescription,
} from '@/components/ui/popover';
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { RESOURCE_TYPES } from '@/core/model';
import type { ActivityResponse, AppState } from '@/core/api-types';
import { api, Check, Field, Picker } from './controls';
import DecisionTable from './decision-table';

type Option = { value: string; label: string };
type Range = { from: string; to: string };
function MultiFilter({
  label,
  options,
  selected,
  onChange,
  searchable = false,
}: {
  label: string;
  options: Option[];
  selected: string[];
  onChange: (value: string[]) => void;
  searchable?: boolean;
}) {
  const [query, setQuery] = useState('');
  const visible = options.filter((o) =>
    o.label.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <Popover onOpenChange={() => setQuery('')}>
      <div className="activity-filter">
        <span>{label}</span>
        <PopoverTrigger
          render={<Button variant="outline" />}
          aria-label={`Filter by ${label}: ${selected.length ? `${selected.length} selected` : 'all'}`}
        >
          <span>{selected.length ? `${selected.length} selected` : 'All'}</span>
          <ChevronDown size={14} />
        </PopoverTrigger>
      </div>
      <PopoverContent align="start" className="activity-filter-menu">
        <PopoverTitle>{label}</PopoverTitle>
        <PopoverDescription>Leave empty to include all.</PopoverDescription>
        {searchable && (
          <div className="search-field">
            <Search size={15} />
            <Input
              aria-label={`Search ${label.toLowerCase()} options`}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={`Search ${label.toLowerCase()}…`}
            />
          </div>
        )}
        <div className="activity-filter-options">
          {visible.map((o) => (
            <Check
              key={o.value}
              checked={selected.includes(o.value)}
              onChange={(checked) =>
                onChange(
                  checked
                    ? [...selected, o.value]
                    : selected.filter((value) => value !== o.value),
                )
              }
            >
              {o.label}
            </Check>
          ))}
          {!visible.length && <p className="help">No matching options.</p>}
        </div>
        <div className="activity-filter-actions">
          <Button
            variant="ghost"
            size="sm"
            disabled={!visible.length}
            onClick={() =>
              onChange([
                ...new Set([...selected, ...visible.map((o) => o.value)]),
              ])
            }
          >
            Select {query ? 'matches' : 'all'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={!selected.length}
            aria-label={`Clear ${label.toLowerCase()} filter`}
            onClick={() => onChange([])}
          >
            Clear
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
function DateFilter({
  range,
  onChange,
}: {
  range: Range;
  onChange: (range: Range) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(range);
  const [error, setError] = useState('');
  const active = !!(range.from || range.to);
  function apply() {
    const start = draft.from ? new Date(draft.from).getTime() : -Infinity;
    const end = draft.to ? new Date(draft.to).getTime() : Infinity;
    if (Number.isNaN(start) || Number.isNaN(end)) {
      setError('Enter valid dates and times.');
      return;
    }
    if (start > end) {
      setError('Start must be before or equal to end.');
      return;
    }
    onChange(draft);
    setOpen(false);
  }
  return (
    <Popover
      open={open}
      onOpenChange={(value) => {
        setOpen(value);
        if (value) {
          setDraft(range);
          setError('');
        }
      }}
    >
      <div className="activity-date-filter">
        <PopoverTrigger
          render={
            <Button variant={active ? 'default' : 'outline'} size="icon" />
          }
          aria-label={
            active
              ? 'Edit activity date and time range (active)'
              : 'Filter activity by date and time'
          }
          title="Date and time range"
        >
          <CalendarDays size={19} />
        </PopoverTrigger>
      </div>
      <PopoverContent align="end" className="activity-date-menu">
        <PopoverTitle>Date and time range</PopoverTitle>
        <PopoverDescription>
          Times are in {new Intl.DateTimeFormat().resolvedOptions().timeZone}.
          Leave either end blank for an open range.
        </PopoverDescription>
        <Field label="From">
          <Input
            type="datetime-local"
            step="1"
            value={draft.from}
            onChange={(e) => {
              setDraft({ ...draft, from: e.target.value });
              setError('');
            }}
          />
        </Field>
        <Field label="To">
          <Input
            type="datetime-local"
            step="1"
            value={draft.to}
            onChange={(e) => {
              setDraft({ ...draft, to: e.target.value });
              setError('');
            }}
          />
        </Field>
        {error && (
          <p className="error-box" role="alert">
            {error}
          </p>
        )}
        <div className="activity-filter-actions">
          <Button
            variant="ghost"
            onClick={() => {
              onChange({ from: '', to: '' });
              setOpen(false);
            }}
          >
            Clear range
          </Button>
          <Button onClick={apply}>Apply range</Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
export default function ActivityPanel({ state }: { state: AppState }) {
  const [type, setType] = useState('platform');
  const [environments, setEnvironments] = useState<string[]>([]);
  const [policies, setPolicies] = useState<string[]>([]);
  const [resources, setResources] = useState<string[]>([]);
  const [principals, setPrincipals] = useState<string[]>([]);
  const [names, setNames] = useState<string[]>([]);
  const [range, setRange] = useState<Range>({ from: '', to: '' });
  const params = new URLSearchParams({ type });
  for (const [key, values] of [
    ['environment', environments],
    ['policy', policies],
    ['resource', resources],
    ['principal', principals],
  ] as const)
    for (const value of values) params.append(key, value);
  if (range.from) params.set('from', new Date(range.from).toISOString());
  if (range.to) params.set('to', new Date(range.to).toISOString());
  const query = params.toString();
  const filtered =
    environments.length +
      policies.length +
      resources.length +
      principals.length >
      0 || !!(range.from || range.to);
  const rangeLabel = [
    range.from ? new Date(range.from).toLocaleString() : 'Any start',
    range.to ? new Date(range.to).toLocaleString() : 'Any end',
  ].join(' → ');
  return (
    <>
      <div className="section-bar activity-toolbar">
        <h2>Event stream</h2>
        <div className="activity-filters">
          <div className="activity-filter activity-type-filter">
            <span>Type</span>
            <Picker
              label="Activity type"
              value={type}
              onChange={setType}
              options={[
                { value: 'platform', label: 'Platform' },
                { value: 'decision', label: 'Policy decisions' },
              ]}
            />
          </div>
          <MultiFilter
            label="Environment"
            options={state.environments
              .map((e) => ({ value: e.id, label: e.name }))
              .sort((a, b) => a.label.localeCompare(b.label))}
            selected={environments}
            onChange={setEnvironments}
            searchable
          />
          <MultiFilter
            label="Policy"
            options={state.policies
              .map((p) => ({ value: p.id, label: p.name }))
              .sort((a, b) => a.label.localeCompare(b.label))}
            selected={policies}
            onChange={setPolicies}
            searchable
          />
          <MultiFilter
            label="Resource"
            options={RESOURCE_TYPES.map((value) => ({ value, label: value }))}
            selected={resources}
            onChange={setResources}
          />
          <MultiFilter
            label="Principal"
            options={[...new Set([...names, ...principals])].map((value) => ({
              value,
              label: value,
            }))}
            selected={principals}
            onChange={setPrincipals}
            searchable
          />
          <DateFilter range={range} onChange={setRange} />
        </div>
      </div>
      {filtered && (
        <div className="activity-filter-summary">
          <span>
            {environments.length
              ? `${environments.length} environments · `
              : ''}
            {policies.length ? `${policies.length} policies · ` : ''}
            {resources.length ? `${resources.length} resource types · ` : ''}
            {principals.length ? `${principals.length} principals · ` : ''}
            {range.from || range.to ? rangeLabel : 'All dates'}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setEnvironments([]);
              setPolicies([]);
              setResources([]);
              setPrincipals([]);
              setRange({ from: '', to: '' });
            }}
          >
            <X size={14} />
            Clear filters
          </Button>
        </div>
      )}
      <ActivityResults
        key={query}
        query={query}
        state={state}
        type={type}
        onNames={setNames}
      />
    </>
  );
}
function ActivityResults({
  query,
  state,
  type,
  onNames,
}: {
  query: string;
  state: AppState;
  type: string;
  onNames: (names: string[]) => void;
}) {
  const [data, setData] = useState<ActivityResponse>();
  const [error, setError] = useState('');
  const [moreBusy, setMoreBusy] = useState(false);
  const [retry, setRetry] = useState(0);
  const generation = useRef(0);
  const viewingHistory = useRef(false);
  const [historyPaused, setHistoryPaused] = useState(false);
  useEffect(() => {
    const current = ++generation.current;
    let pending = false;
    const load = () => {
      if (
        pending ||
        viewingHistory.current ||
        document.visibilityState === 'hidden'
      )
        return;
      pending = true;
      void api<ActivityResponse>('activity?' + query)
        .then((response) => {
          if (generation.current !== current || viewingHistory.current) return;
          setData(response);
          onNames(response.principals);
          setError('');
          setMoreBusy(false);
        })
        .catch((e: Error) => {
          if (generation.current === current && !viewingHistory.current) {
            setError(e.message);
            setMoreBusy(false);
          }
        })
        .finally(() => {
          pending = false;
        });
    };
    const timer = setTimeout(load, 150);
    const interval = setInterval(load, 15000);
    window.addEventListener('focus', load);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
      window.removeEventListener('focus', load);
      generation.current = current + 1;
    };
  }, [query, state, retry, onNames]);
  async function more() {
    if (!data?.nextCursor || moreBusy) return;
    const current = generation.current;
    viewingHistory.current = true;
    setHistoryPaused(true);
    setMoreBusy(true);
    setError('');
    try {
      const params = new URLSearchParams(query);
      params.set('cursor', data.nextCursor);
      const response = await api<ActivityResponse>(
        'activity?' + params.toString(),
      );
      if (current === generation.current)
        setData({ ...response, events: [...data.events, ...response.events] });
    } catch (e) {
      if (current === generation.current) setError((e as Error).message);
    } finally {
      if (current === generation.current) setMoreBusy(false);
    }
  }
  return (
    <>
      {error && (
        <div className="error-box" role="alert">
          <span>{error}</span>
          <Button
            variant="outline"
            onClick={() => {
              viewingHistory.current = false;
              setHistoryPaused(false);
              setRetry((n) => n + 1);
            }}
          >
            Retry
          </Button>
        </div>
      )}
      <div className="surface" aria-busy={!data && !error}>
        {type === 'decision' ? (
          <DecisionTable
            events={data?.events ?? []}
            environments={state.environments}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>EVENT</TableHead>
                <TableHead>RESULT</TableHead>
                <TableHead>SOURCE</TableHead>
                <TableHead>TIME</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.events.map((event) => (
                <TableRow key={event.recordId ?? event.id}>
                  <TableCell>
                    <strong>
                      {event.operation} {event.objectType ?? 'client'}
                    </strong>
                    <small className="block muted mt-1">
                      {event.name ?? event.note}
                    </small>
                  </TableCell>
                  <TableCell>
                    <span className="badge neutral">
                      {event.effectiveResult ?? event.mode ?? 'Recorded'}
                    </span>
                  </TableCell>
                  <TableCell>{event.actor ?? 'Control plane'}</TableCell>
                  <TableCell>
                    <time dateTime={event.time}>
                      {new Date(event.time).toLocaleString()}
                    </time>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {!data && !error && (
          <div className="empty">
            <p>Loading activity…</p>
          </div>
        )}
        {data && !data.events.length && (
          <div className="empty">
            <h3>No matching activity</h3>
            <p>Try different filters or a wider date and time range.</p>
          </div>
        )}
      </div>
      {data && (
        <div className="activity-pagination">
          <output>
            {data.events.length} of {data.total} matching events
          </output>
          <Button
            variant="outline"
            disabled={moreBusy}
            onClick={() => {
              viewingHistory.current = false;
              setHistoryPaused(false);
              setRetry((n) => n + 1);
            }}
          >
            <RefreshCw size={14} /> Refresh
          </Button>
          {data.nextCursor && (
            <Button
              variant="outline"
              disabled={moreBusy}
              onClick={() => void more()}
            >
              {moreBusy ? 'Loading…' : 'Load more'}
            </Button>
          )}
          <span className="help">
            {historyPaused
              ? 'Auto-refresh paused while viewing older events. '
              : 'Updates every 15 seconds. '}
            Times shown in{' '}
            {new Intl.DateTimeFormat().resolvedOptions().timeZone}
          </span>
        </div>
      )}
    </>
  );
}

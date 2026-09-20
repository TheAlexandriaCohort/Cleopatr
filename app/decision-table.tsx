'use client';
import { useId, useState } from 'react';
import { ChevronRight, Copy, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import type { EventRecord } from '@/core/api-types';
import type { Environment } from '@/core/model';

export default function DecisionTable({
  events,
  environments = [],
}: {
  events: EventRecord[];
  environments?: Environment[];
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>DATE / TIME</TableHead>
          <TableHead>POLICY INVOKED</TableHead>
          <TableHead>POLICY DECISION</TableHead>
          <TableHead>CLEO CLIENT</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((event) => (
          <DecisionRow
            key={event.recordId ?? `${event.clientId ?? ''}:${event.id}`}
            event={event}
            environments={environments}
          />
        ))}
      </TableBody>
    </Table>
  );
}

function DecisionRow({
  event,
  environments,
}: {
  event: EventRecord;
  environments: Environment[];
}) {
  const [open, setOpen] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');
  const detailId = useId();
  const titleId = useId();
  const name =
    event.policyName ||
    event.policyId ||
    event.determiningPolicies?.join(', ') ||
    'Default deny';
  const assessment = event.assessment;
  const payload =
    assessment?.status === 'captured' ? assessment.payload : undefined;
  const json = payload ? JSON.stringify(payload, null, 2) : undefined;
  const toggle = () => setOpen((value) => !value);
  async function copy() {
    try {
      await navigator.clipboard.writeText(json!);
      setCopyStatus('Copied');
    } catch {
      setCopyStatus(
        'Could not copy. Select the JSON below to copy it manually.',
      );
    }
  }
  return (
    <>
      <TableRow
        className="decision-event-row"
        data-expanded={open}
        onClick={toggle}
      >
        <TableCell>
          <div className="decision-event-time">
            <Button
              variant="ghost"
              size="icon-sm"
              aria-expanded={open}
              aria-controls={detailId}
              aria-label={`${open ? 'Hide' : 'Show'} assessed payload for ${name} at ${new Date(event.time).toLocaleString()}`}
              onClick={(e) => {
                e.stopPropagation();
                toggle();
              }}
            >
              <ChevronRight
                className={
                  open ? 'decision-chevron is-open' : 'decision-chevron'
                }
                aria-hidden="true"
              />
            </Button>
            <time dateTime={event.time}>
              {new Date(event.time).toLocaleString()}
            </time>
          </div>
        </TableCell>
        <TableCell>
          <strong>{name}</strong>
          <small className="block muted mt-1">
            {event.action}
            {event.policyVersion ? ` · v${event.policyVersion}` : ''}
          </small>
          {event.environmentId && (
            <small className="block muted mt-1">
              {environments.find((e) => e.id === event.environmentId)?.name ??
                event.environmentId}
              {event.resourceType ? ` · ${event.resourceType}` : ''}
            </small>
          )}
        </TableCell>
        <TableCell>
          <span className="badge gold">{event.decision}</span>
          <small className="block muted mt-1">
            {event.mode} · {event.effectiveResult?.replaceAll('_', ' ')}
          </small>
        </TableCell>
        <TableCell>
          {event.clientName ?? event.clientId ?? 'Unknown client'}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="decision-payload-row">
          <TableCell colSpan={4}>
            <section
              id={detailId}
              aria-labelledby={titleId}
              className="decision-payload"
            >
              <div className="decision-payload-heading">
                <div>
                  <h3 id={titleId}>Assessed payload · {name}</h3>
                  <p>
                    The Cedar input captured by cleo when this decision was
                    evaluated.
                  </p>
                </div>
                {json && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void copy()}
                  >
                    {copyStatus === 'Copied' ? (
                      <Check size={15} />
                    ) : (
                      <Copy size={15} />
                    )}
                    {copyStatus === 'Copied' ? 'Copied' : 'Copy JSON'}
                  </Button>
                )}
              </div>
              {copyStatus && <output>{copyStatus}</output>}
              {payload ? (
                <>
                  <p className="decision-payload-principal">
                    Principal{' '}
                    <code>
                      {payload.principal.type}::
                      {JSON.stringify(payload.principal.id)}
                    </code>
                  </p>
                  <pre aria-label={`Cedar payload for ${name}`}>
                    <code>{json}</code>
                  </pre>
                </>
              ) : (
                <p className="decision-payload-empty">
                  {assessment?.status === 'unavailable'
                    ? assessment.reason === 'not_evaluated'
                      ? 'Input validation failed before Cedar evaluation. There is no assessed payload for this event.'
                      : `The payload exceeded the 128 KiB capture limit (${assessment.bytes.toLocaleString()} bytes). Its contents were not stored.`
                    : 'No assessed payload was recorded for this event. New decisions from cleo 0.4.1 include it; earlier events cannot be reconstructed.'}
                </p>
              )}
            </section>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

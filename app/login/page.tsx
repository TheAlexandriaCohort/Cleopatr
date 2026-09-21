'use client';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Field } from '../controls';
export default function Login() {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <main className="login-page">
      <form
        className="login-card"
        onSubmit={async (event) => {
          event.preventDefault();
          setBusy(true);
          setError('');
          try {
            const response = await fetch('/api/session', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ token }),
            });
            if (!response.ok)
              throw new Error(
                (await response.json()).error ?? 'Sign-in failed',
              );
            window.location.assign('/');
          } catch (e) {
            setError((e as Error).message);
            setBusy(false);
          }
        }}
      >
        <h1>Open your workspace.</h1>
        <p>
          Enter the administrator token configured for this Cleopatr server.
        </p>
        <Field label="Administrator token">
          <Input
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            required
          />
        </Field>
        {error && <p role="alert">{error}</p>}
        <Button className="primary-button" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </main>
  );
}
